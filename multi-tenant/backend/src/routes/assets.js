import { Router } from 'express';
import { db } from '../services/database.js';
import { authenticate, requireRole } from '../middleware/auth.js';
import { auditLog } from '../services/audit.js';
import { wsManager } from '../services/websocket.js';
import { z } from 'zod';

const router = Router();
router.use(authenticate);

// Helper for tenant queries (with RLS)
const tq = async (req, sql, params = []) => {
    return db.tenantQuery(req.user.tenant_id, sql, params);
};

// Validation schemas
const UpdateThreatLevelSchema = z.object({
    threat_level: z.enum(['safe', 'warning', 'critical', 'under_attack']),
    reason: z.string().optional()
});

const CreateAssetSchema = z.object({
    name: z.string().min(1).max(150),
    asset_type: z.enum(['aircraft', 'sensor', 'gate', 'radar', 'atc', 'ground_vehicle']).default('aircraft'),
    icao24: z.string().max(10).optional(),
    tail_number: z.string().max(20).optional(),
    airline_code: z.string().max(10).optional(),
    location: z.string().max(150).optional(),
    latitude: z.number().min(-90).max(90).optional(),
    longitude: z.number().min(-180).max(180).optional(),
    altitude_ft: z.number().min(0).max(100000).optional(),
    speed_kts: z.number().min(0).max(2000).optional(),
    heading: z.number().min(0).max(359).optional(),
    squawk: z.string().max(4).optional(),
    criticality: z.number().min(0).max(1).default(0.5),
    is_protected: z.boolean().default(true),
    metadata: z.record(z.any()).optional()
});

const UpdateAssetSchema = CreateAssetSchema.partial();

// ─── GET all assets (with aggregated threat info) ─────────────────────────────
router.get('/', async (req, res) => {
    try {
        const result = await tq(req, `
            SELECT 
                id, name, asset_type, icao24, callsign, registration,
                status, threat_level, latitude, longitude, altitude_ft,
                speed_kts, heading, squawk, location, criticality,
                is_protected, created_at, tail_number, airline_code
            FROM assets
            ORDER BY 
                CASE threat_level 
                    WHEN 'under_attack' THEN 1
                    WHEN 'critical' THEN 2
                    WHEN 'warning' THEN 3
                    ELSE 4
                END,
                criticality DESC,
                name
        `);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error('Assets fetch error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET single asset by ID (with full threat history) ───────────────────────
router.get('/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const [assetResult, threatsResult, alertsResult] = await Promise.all([
            tq(req, `SELECT * FROM assets WHERE id = $1`, [id]),
            tq(req, `
                SELECT 
                    t.*,
                    u.username AS assigned_to_name,
                    EXTRACT(EPOCH FROM (NOW() - t.detected_at)) / 3600 AS hours_ago
                FROM threats t
                LEFT JOIN users u ON t.assigned_to = u.id
                WHERE t.asset_id = $1
                ORDER BY t.detected_at DESC
                LIMIT 50
            `, [id]),
            tq(req, `
                SELECT * FROM alerts 
                WHERE asset_id = $1 
                ORDER BY detected_at DESC 
                LIMIT 20
            `, [id])
        ]);
        
        if (!assetResult.rows.length) {
            return res.status(404).json({ success: false, error: 'Asset not found' });
        }
        
        // Calculate risk score based on recent threats
        const asset = assetResult.rows[0];
        const threats = threatsResult.rows;
        const alerts = alertsResult.rows;
        
        const riskScore = threats.length > 0 
            ? Math.min(100, Math.round(
                (threats.reduce((sum, t) => sum + (t.score || 0.5) * 100, 0) / threats.length) *
                (asset.criticality || 0.5)
              ))
            : Math.round((asset.criticality || 0.5) * 50);
        
        res.json({
            success: true,
            data: {
                ...asset,
                risk_score: riskScore,
                threat_history: threats,
                recent_alerts: alerts,
                stats: {
                    total_threats: threats.length,
                    critical_threats: threats.filter(t => t.severity === 'critical' || t.severity === 'emergency').length,
                    high_threats: threats.filter(t => t.severity === 'high').length,
                    last_threat_at: threats[0]?.detected_at || null
                }
            }
        });
    } catch (err) {
        console.error('Asset detail error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET threats for specific asset ──────────────────────────────────────────
router.get('/:id/threats', async (req, res) => {
    const { id } = req.params;
    const { limit = 50, severity, from, to } = req.query;
    
    let query = `
        SELECT t.*, u.username AS assigned_to_name
        FROM threats t
        LEFT JOIN users u ON t.assigned_to = u.id
        WHERE t.asset_id = $1
    `;
    const params = [id];
    let paramIdx = 2;
    
    if (severity) {
        query += ` AND t.severity = $${paramIdx++}`;
        params.push(severity);
    }
    if (from) {
        query += ` AND t.detected_at >= $${paramIdx++}`;
        params.push(from);
    }
    if (to) {
        query += ` AND t.detected_at <= $${paramIdx++}`;
        params.push(to);
    }
    
    query += ` ORDER BY t.detected_at DESC LIMIT $${paramIdx++}`;
    params.push(parseInt(limit));
    
    try {
        const result = await tq(req, query, params);
        res.json({ success: true, data: result.rows, count: result.rows.length });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── UPDATE threat level (with audit and WebSocket broadcast) ─────────────────
router.patch('/:id/threat-level', requireRole('admin', 'analyst'), async (req, res) => {
    const { id } = req.params;
    const validation = UpdateThreatLevelSchema.safeParse(req.body);
    
    if (!validation.success) {
        return res.status(400).json({ success: false, error: validation.error.errors });
    }
    
    const { threat_level, reason } = validation.data;
    
    try {
        const result = await tq(req, `
            UPDATE assets 
            SET threat_level = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING *
        `, [threat_level, id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Asset not found' });
        }
        
        // Broadcast to WebSocket clients in same tenant
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'asset_threat_level_changed',
            data: {
                asset_id: id,
                threat_level,
                previous_level: result.rows[0].threat_level,
                updated_by: req.user.username,
                reason,
                timestamp: new Date().toISOString()
            }
        });
        
        // Audit log
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'UPDATE_THREAT_LEVEL',
            resource: 'asset',
            resourceId: id,
            details: { threat_level, reason },
            ip: req.ip
        });
        
        res.json({ 
            success: true, 
            data: result.rows[0],
            message: `Threat level updated to ${threat_level}`
        });
    } catch (err) {
        console.error('Update threat level error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── CREATE new asset (admin only) ───────────────────────────────────────────
router.post('/', requireRole('admin'), async (req, res) => {
    const validation = CreateAssetSchema.safeParse(req.body);
    
    if (!validation.success) {
        return res.status(400).json({ success: false, error: validation.error.errors });
    }
    
    const data = validation.data;
    
    try {
        const result = await tq(req, `
            INSERT INTO assets (
                tenant_id, name, asset_type, icao24, tail_number, airline_code,
                location, latitude, longitude, altitude_ft, speed_kts, heading,
                squawk, criticality, is_protected, metadata
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
            ) RETURNING *
        `, [
            req.user.tenant_id,
            data.name,
            data.asset_type,
            data.icao24 || null,
            data.tail_number || null,
            data.airline_code || null,
            data.location || null,
            data.latitude || null,
            data.longitude || null,
            data.altitude_ft || null,
            data.speed_kts || null,
            data.heading || null,
            data.squawk || null,
            data.criticality,
            data.is_protected,
            data.metadata ? JSON.stringify(data.metadata) : null
        ]);
        
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'asset_created',
            data: result.rows[0]
        });
        
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'CREATE_ASSET',
            resource: 'asset',
            resourceId: result.rows[0].id,
            details: { name: data.name, asset_type: data.asset_type },
            ip: req.ip
        });
        
        res.status(201).json({ success: true, data: result.rows[0] });
    } catch (err) {
        console.error('Create asset error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── UPDATE asset (admin only) ───────────────────────────────────────────────
router.patch('/:id', requireRole('admin'), async (req, res) => {
    const { id } = req.params;
    const validation = UpdateAssetSchema.safeParse(req.body);
    
    if (!validation.success) {
        return res.status(400).json({ success: false, error: validation.error.errors });
    }
    
    const updates = validation.data;
    const setClauses = [];
    const values = [];
    let idx = 1;
    
    for (const [key, value] of Object.entries(updates)) {
        if (value !== undefined) {
            setClauses.push(`${key} = $${idx++}`);
            values.push(value);
        }
    }
    
    if (setClauses.length === 0) {
        return res.status(400).json({ success: false, error: 'No fields to update' });
    }
    
    setClauses.push(`updated_at = NOW()`);
    values.push(id);
    
    try {
        const result = await tq(req, `
            UPDATE assets 
            SET ${setClauses.join(', ')}
            WHERE id = $${values.length}
            RETURNING *
        `, values);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Asset not found' });
        }
        
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'asset_updated',
            data: result.rows[0]
        });
        
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'UPDATE_ASSET',
            resource: 'asset',
            resourceId: id,
            details: updates,
            ip: req.ip
        });
        
        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        console.error('Update asset error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── ISOLATE asset (analyst+) — quarantine on suspected compromise ──────────
// Records isolation flag in metadata and flips status to 'compromised' until
// cleared. Idempotent: re-POSTing with isolated:false un-isolates.
router.post('/:id/isolate', requireRole('admin', 'analyst'), async (req, res) => {
    const { id } = req.params;
    const isolated = req.body?.isolated !== false; // default true
    const reason = (req.body?.reason || '').slice(0, 500);

    try {
        const cur = await tq(req, `SELECT id, name, icao24, metadata, status FROM assets WHERE id = $1`, [id]);
        if (!cur.rows.length) {
            return res.status(404).json({ success: false, error: 'Asset not found' });
        }
        const meta = { ...(cur.rows[0].metadata || {}) };
        if (isolated) {
            meta.isolated = true;
            meta.isolated_at = new Date().toISOString();
            meta.isolated_by = req.user.username;
            meta.isolation_reason = reason || 'manual';
        } else {
            meta.isolated = false;
            meta.unisolated_at = new Date().toISOString();
            meta.unisolated_by = req.user.username;
        }
        const nextStatus = isolated ? 'compromised' : 'active';

        const upd = await tq(req,
            `UPDATE assets SET metadata = $1::jsonb, status = $2 WHERE id = $3 RETURNING *`,
            [JSON.stringify(meta), nextStatus, id]);

        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'asset:isolated',
            data: {
                asset_id: Number(id),
                icao24: upd.rows[0].icao24,
                isolated,
                reason,
                by: req.user.username,
                at: meta.isolated_at || meta.unisolated_at,
            },
        });
        // also fire the canonical asset_updated event so any list view refreshes
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'asset_updated',
            data: upd.rows[0],
        });

        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: isolated ? 'ISOLATE_ASSET' : 'UNISOLATE_ASSET',
            resource: 'asset',
            resourceId: id,
            details: { reason },
            ip: req.ip,
        });

        res.json({ success: true, data: upd.rows[0] });
    } catch (err) {
        console.error('Isolate asset error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── DELETE asset (admin only) ───────────────────────────────────────────────
router.delete('/:id', requireRole('admin'), async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await tq(req, `DELETE FROM assets WHERE id = $1 RETURNING id, name`, [id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Asset not found' });
        }
        
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'asset_deleted',
            data: { id, name: result.rows[0].name }
        });
        
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'DELETE_ASSET',
            resource: 'asset',
            resourceId: id,
            details: { name: result.rows[0].name },
            ip: req.ip
        });
        
        res.json({ success: true, message: 'Asset deleted successfully' });
    } catch (err) {
        console.error('Delete asset error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET asset statistics (summary) ──────────────────────────────────────────
router.get('/stats/summary', async (req, res) => {
    try {
        const result = await tq(req, `
            SELECT 
                COUNT(*) AS total,
                COUNT(CASE WHEN status = 'active' THEN 1 END) AS active,
                COUNT(CASE WHEN threat_level = 'under_attack' THEN 1 END) AS under_attack,
                COUNT(CASE WHEN threat_level = 'critical' THEN 1 END) AS critical,
                COUNT(CASE WHEN threat_level = 'warning' THEN 1 END) AS warning,
                COUNT(CASE WHEN is_protected = TRUE THEN 1 END) AS protected,
                COUNT(CASE WHEN asset_type = 'aircraft' THEN 1 END) AS aircraft_count
            FROM assets
        `);
        
        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

export default router;