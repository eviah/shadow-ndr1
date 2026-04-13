import { Router } from 'express';
import { z } from 'zod';
import { db } from '../services/database.js';
import { authenticate } from '../middleware/auth.js';
import { auditLog } from '../services/audit.js';
import { wsManager } from '../services/websocket.js';
import { logger } from '../utils/logger.js';

const router = Router();
router.use(authenticate);

// Helper for tenant queries
const tq = async (req, sql, params = []) => {
    return db.tenantQuery(req.user.tenant_id, sql, params);
};

// Validation schemas
const CreateThreatSchema = z.object({
    asset_id: z.string().uuid().optional(),
    threat_type: z.string().min(1).max(100),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical', 'emergency']),
    source_ip: z.string().ip().optional(),
    dest_ip: z.string().ip().optional(),
    icao24: z.string().max(10).optional(),
    score: z.number().min(0).max(1).default(0.5),
    description: z.string().max(2000).optional(),
    mitre_technique: z.string().max(20).optional(),
    raw_payload: z.record(z.any()).optional(),
    tags: z.array(z.string()).optional()
});

const UpdateStatusSchema = z.object({
    status: z.enum(['active', 'investigating', 'resolved', 'fp']),
    notes: z.string().optional()
});

const AssignSchema = z.object({
    assigned_to: z.string().uuid(),
    notes: z.string().optional()
});

// ─── GET all threats (with filters and pagination) ───────────────────────────
router.get('/', async (req, res) => {
    try {
        const result = await tq(req, `
            SELECT 
                id, threat_type, severity, source_ip, dest_ip, icao24,
                score, description, mitre_technique, status,
                detected_at, resolved_at, asset_id
            FROM threats
            ORDER BY detected_at DESC
            LIMIT 100
        `);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error('Threats fetch error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET single threat by ID (with full details) ─────────────────────────────
router.get('/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await tq(req, `
            SELECT 
                t.*,
                a.name AS aircraft_name,
                a.icao24 AS aircraft_icao,
                a.tail_number,
                a.airline_code,
                a.location,
                a.latitude,
                a.longitude,
                a.altitude_ft,
                a.speed_kts,
                a.threat_level AS asset_threat_level,
                a.is_protected,
                u.username AS assigned_to_name,
                creator.username AS created_by_name
            FROM threats t
            LEFT JOIN assets a ON t.asset_id = a.id
            LEFT JOIN users u ON t.assigned_to = u.id
            LEFT JOIN users creator ON t.created_by = creator.id
            WHERE t.id = $1
        `, [id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Threat not found' });
        }
        
        // Get related events (alerts, actions)
        const relatedResult = await tq(req, `
            SELECT * FROM alerts 
            WHERE threat_id = $1 
            ORDER BY detected_at DESC 
            LIMIT 10
        `, [id]);
        
        res.json({
            success: true,
            data: {
                ...result.rows[0],
                related_alerts: relatedResult.rows
            }
        });
    } catch (err) {
        logger.error({ err: err.message, threat_id: id }, 'Threat detail error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── CREATE new threat ───────────────────────────────────────────────────────
router.post('/', async (req, res) => {
    const validation = CreateThreatSchema.safeParse(req.body);
    
    if (!validation.success) {
        return res.status(400).json({ 
            success: false, 
            error: 'Validation failed',
            details: validation.error.errors 
        });
    }
    
    const data = validation.data;
    
    try {
        const result = await tq(req, `
            INSERT INTO threats (
                tenant_id, asset_id, threat_type, severity, 
                source_ip, dest_ip, icao24, score, description, 
                mitre_technique, raw_payload, tags, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
        `, [
            req.user.tenant_id,
            data.asset_id || null,
            data.threat_type,
            data.severity,
            data.source_ip || null,
            data.dest_ip || null,
            data.icao24 || null,
            data.score,
            data.description || null,
            data.mitre_technique || null,
            data.raw_payload ? JSON.stringify(data.raw_payload) : null,
            data.tags ? JSON.stringify(data.tags) : null,
            req.user.id
        ]);
        
        const threat = result.rows[0];
        
        // Update asset threat level if critical/emergency
        if (data.asset_id && ['critical', 'emergency'].includes(data.severity)) {
            await tq(req, `
                UPDATE assets 
                SET threat_level = 'under_attack', updated_at = NOW() 
                WHERE id = $1
            `, [data.asset_id]);
            
            // Also create an alert for critical threats
            await tq(req, `
                INSERT INTO alerts (tenant_id, asset_id, threat_id, title, severity, message)
                VALUES ($1, $2, $3, $4, $5, $6)
            `, [
                req.user.tenant_id,
                data.asset_id,
                threat.id,
                `${data.threat_type} - ${data.severity.toUpperCase()}`,
                data.severity,
                data.description || `Critical threat detected on asset`
            ]);
        }
        
        // Broadcast to WebSocket clients
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'new_threat',
            data: threat,
            timestamp: new Date().toISOString()
        });
        
        // Audit log
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'CREATE_THREAT',
            resource: 'threat',
            resourceId: threat.id,
            details: { threat_type: data.threat_type, severity: data.severity, asset_id: data.asset_id },
            ip: req.ip
        });
        
        res.status(201).json({ success: true, data: threat });
    } catch (err) {
        logger.error({ err: err.message, body: req.body }, 'Create threat error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── UPDATE threat status ────────────────────────────────────────────────────
router.patch('/:id/status', async (req, res) => {
    const { id } = req.params;
    const validation = UpdateStatusSchema.safeParse(req.body);
    
    if (!validation.success) {
        return res.status(400).json({ success: false, error: validation.error.errors });
    }
    
    const { status, notes } = validation.data;
    
    try {
        const result = await tq(req, `
            UPDATE threats 
            SET status = $1, 
                resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE resolved_at END,
                updated_at = NOW(),
                notes = COALESCE(notes, '[]') || $2::jsonb
            WHERE id = $3
            RETURNING *
        `, [status, notes ? JSON.stringify([notes]) : '[]', id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Threat not found' });
        }
        
        // Broadcast update
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'threat_updated',
            data: { id, status, notes },
            timestamp: new Date().toISOString()
        });
        
        // Audit log
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'UPDATE_THREAT_STATUS',
            resource: 'threat',
            resourceId: id,
            details: { status, notes },
            ip: req.ip
        });
        
        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        logger.error({ err: err.message, threat_id: id }, 'Update threat status error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── ASSIGN threat to user ───────────────────────────────────────────────────
router.patch('/:id/assign', async (req, res) => {
    const { id } = req.params;
    const validation = AssignSchema.safeParse(req.body);
    
    if (!validation.success) {
        return res.status(400).json({ success: false, error: validation.error.errors });
    }
    
    const { assigned_to, notes } = validation.data;
    
    try {
        // Verify user exists and belongs to same tenant
        const userCheck = await tq(req, `SELECT id FROM users WHERE id = $1`, [assigned_to]);
        if (!userCheck.rows.length) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const result = await tq(req, `
            UPDATE threats 
            SET assigned_to = $1, updated_at = NOW(),
                notes = COALESCE(notes, '[]') || $2::jsonb
            WHERE id = $3
            RETURNING *
        `, [assigned_to, notes ? JSON.stringify([notes]) : '[]', id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Threat not found' });
        }
        
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'threat_assigned',
            data: { id, assigned_to, assigned_by: req.user.username }
        });
        
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'ASSIGN_THREAT',
            resource: 'threat',
            resourceId: id,
            details: { assigned_to, notes },
            ip: req.ip
        });
        
        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        logger.error({ err: err.message, threat_id: id }, 'Assign threat error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET threat statistics (dashboard summary) ───────────────────────────────
router.get('/stats/summary', async (req, res) => {
    const { days = 7 } = req.query;
    
    try {
        const result = await tq(req, `
            SELECT 
                COUNT(*) AS total,
                COUNT(CASE WHEN severity = 'critical' THEN 1 END) AS critical,
                COUNT(CASE WHEN severity = 'emergency' THEN 1 END) AS emergency,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) AS high,
                COUNT(CASE WHEN severity = 'medium' THEN 1 END) AS medium,
                COUNT(CASE WHEN status = 'active' THEN 1 END) AS active,
                COUNT(CASE WHEN status = 'investigating' THEN 1 END) AS investigating,
                COUNT(CASE WHEN status = 'resolved' THEN 1 END) AS resolved,
                AVG(score) AS avg_score,
                MAX(score) AS max_score
            FROM threats
            WHERE detected_at > NOW() - INTERVAL '${days} days'
        `);
        
        // Top attack types
        const topAttacks = await tq(req, `
            SELECT threat_type, COUNT(*) AS count
            FROM threats
            WHERE detected_at > NOW() - INTERVAL '7 days'
            GROUP BY threat_type
            ORDER BY count DESC
            LIMIT 10
        `);
        
        // Timeline (daily)
        const timeline = await tq(req, `
            SELECT 
                DATE_TRUNC('day', detected_at) AS day,
                COUNT(*) AS count,
                AVG(score) AS avg_score
            FROM threats
            WHERE detected_at > NOW() - INTERVAL '30 days'
            GROUP BY DATE_TRUNC('day', detected_at)
            ORDER BY day ASC
        `);
        
        res.json({
            success: true,
            data: {
                summary: result.rows[0],
                top_attack_types: topAttacks.rows,
                timeline: timeline.rows,
                period_days: parseInt(days)
            }
        });
    } catch (err) {
        logger.error({ err: err.message }, 'Threat stats error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── DELETE threat (admin only) ─────────────────────────────────────────────
router.delete('/:id', async (req, res) => {
    const { id } = req.params;
    
    // Check if user is admin (you can add role check middleware)
    if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, error: 'Admin access required' });
    }
    
    try {
        const result = await tq(req, `DELETE FROM threats WHERE id = $1 RETURNING id, threat_type`, [id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Threat not found' });
        }
        
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'DELETE_THREAT',
            resource: 'threat',
            resourceId: id,
            details: { threat_type: result.rows[0].threat_type },
            ip: req.ip
        });
        
        res.json({ success: true, message: 'Threat deleted successfully' });
    } catch (err) {
        logger.error({ err: err.message, threat_id: id }, 'Delete threat error');
        res.status(500).json({ success: false, error: err.message });
    }
});

export default router;