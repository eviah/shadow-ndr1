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
const CreateAlertSchema = z.object({
    asset_id: z.string().uuid().optional(),
    threat_id: z.string().uuid().optional(),
    title: z.string().min(1).max(300),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical', 'emergency']),
    message: z.string().max(2000).optional(),
    source: z.string().max(100).optional()
});

const AcknowledgeSchema = z.object({
    notes: z.string().max(500).optional()
});

// ─── GET all alerts (with filters and pagination) ────────────────────────────
router.get('/', async (req, res) => {
    const { 
        severity, acknowledged, from, to, 
        limit = 50, page = 1, asset_id 
    } = req.query;
    
    const conditions = ['1=1'];
    const params = [];
    let paramIdx = 1;
    
    if (severity) {
        conditions.push(`al.severity = $${paramIdx++}`);
        params.push(severity);
    }
    if (acknowledged !== undefined) {
        conditions.push(`al.acknowledged = $${paramIdx++}`);
        params.push(acknowledged === 'true');
    }
    if (from) {
        conditions.push(`al.detected_at >= $${paramIdx++}`);
        params.push(new Date(from));
    }
    if (to) {
        conditions.push(`al.detected_at <= $${paramIdx++}`);
        params.push(new Date(to));
    }
    if (asset_id) {
        conditions.push(`al.asset_id = $${paramIdx++}`);
        params.push(asset_id);
    }
    
    const whereClause = conditions.join(' AND ');
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    try {
        const [alerts, countResult] = await Promise.all([
            tq(req, `
                SELECT 
                    al.*,
                    a.name AS aircraft_name,
                    a.icao24 AS aircraft_icao,
                    a.tail_number,
                    a.location,
                    a.threat_level AS asset_threat_level,
                    u.username AS ack_by_name,
                    EXTRACT(EPOCH FROM (NOW() - al.detected_at)) / 60 AS minutes_ago
                FROM alerts al
                LEFT JOIN assets a ON al.asset_id = a.id
                LEFT JOIN users u ON al.ack_by = u.id
                WHERE ${whereClause}
                ORDER BY 
                    CASE WHEN al.acknowledged = FALSE THEN 0 ELSE 1 END,
                    al.severity = 'emergency' DESC,
                    al.severity = 'critical' DESC,
                    al.detected_at DESC
                LIMIT $${paramIdx++} OFFSET $${paramIdx++}
            `, [...params, parseInt(limit), offset]),
            tq(req, `SELECT COUNT(*)::INT AS total FROM alerts al WHERE ${whereClause}`, params)
        ]);
        
        // Calculate unacknowledged count
        const unackedResult = await tq(req, `
            SELECT COUNT(*)::INT AS unacknowledged
            FROM alerts
            WHERE acknowledged = FALSE
        `);
        
        res.json({
            success: true,
            data: alerts.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: countResult.rows[0].total,
                pages: Math.ceil(countResult.rows[0].total / parseInt(limit))
            },
            stats: {
                unacknowledged: unackedResult.rows[0].unacknowledged
            },
            filters: { severity, acknowledged, from, to, asset_id },
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        logger.error({ err: err.message }, 'Alerts fetch error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET single alert by ID ──────────────────────────────────────────────────
router.get('/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await tq(req, `
            SELECT 
                al.*,
                a.name AS aircraft_name,
                a.icao24 AS aircraft_icao,
                a.tail_number,
                a.location,
                a.latitude,
                a.longitude,
                a.altitude_ft,
                a.speed_kts,
                a.threat_level AS asset_threat_level,
                a.is_protected,
                u.username AS ack_by_name,
                t.threat_type,
                t.severity AS threat_severity,
                t.score AS threat_score
            FROM alerts al
            LEFT JOIN assets a ON al.asset_id = a.id
            LEFT JOIN users u ON al.ack_by = u.id
            LEFT JOIN threats t ON al.threat_id = t.id
            WHERE al.id = $1
        `, [id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Alert not found' });
        }
        
        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        logger.error({ err: err.message, alert_id: id }, 'Alert detail error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── CREATE new alert (internal use) ─────────────────────────────────────────
router.post('/', async (req, res) => {
    const validation = CreateAlertSchema.safeParse(req.body);
    
    if (!validation.success) {
        return res.status(400).json({ 
            success: false, 
            error: 'Validation failed',
            details: validation.error.errors 
        });
    }
    
    const data = validation.data;
    
    try {
        // Check for duplicate alert in last 5 minutes
        const dupCheck = await tq(req, `
            SELECT id FROM alerts 
            WHERE asset_id = $1 AND title = $2 AND detected_at > NOW() - INTERVAL '5 minutes'
            LIMIT 1
        `, [data.asset_id || null, data.title]);
        
        if (dupCheck.rows.length) {
            logger.info(`Duplicate alert suppressed: ${data.title}`);
            return res.status(409).json({ 
                success: false, 
                error: 'Duplicate alert suppressed',
                existing_id: dupCheck.rows[0].id
            });
        }
        
        const result = await tq(req, `
            INSERT INTO alerts (
                tenant_id, asset_id, threat_id, title, severity, message, source
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
        `, [
            req.user.tenant_id,
            data.asset_id || null,
            data.threat_id || null,
            data.title,
            data.severity,
            data.message || null,
            data.source || 'system'
        ]);
        
        const alert = result.rows[0];
        
        // Broadcast to WebSocket clients
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'new_alert',
            data: alert,
            timestamp: new Date().toISOString()
        });
        
        // Audit log
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'CREATE_ALERT',
            resource: 'alert',
            resourceId: alert.id,
            details: { title: data.title, severity: data.severity, asset_id: data.asset_id },
            ip: req.ip
        });
        
        res.status(201).json({ success: true, data: alert });
    } catch (err) {
        logger.error({ err: err.message, body: req.body }, 'Create alert error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── ACKNOWLEDGE alert ───────────────────────────────────────────────────────
router.post('/:id/acknowledge', async (req, res) => {
    const { id } = req.params;
    const validation = AcknowledgeSchema.safeParse(req.body);
    
    if (!validation.success) {
        return res.status(400).json({ success: false, error: validation.error.errors });
    }
    
    const { notes } = validation.data;
    
    try {
        const result = await tq(req, `
            UPDATE alerts 
            SET acknowledged = TRUE, 
                ack_by = $1, 
                ack_at = NOW(),
                ack_notes = COALESCE(ack_notes, '[]') || $2::jsonb
            WHERE id = $3
            RETURNING *
        `, [req.user.id, notes ? JSON.stringify([notes]) : '[]', id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Alert not found' });
        }
        
        // Broadcast to WebSocket
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'alert_acknowledged',
            data: { 
                id, 
                ack_by: req.user.username,
                ack_at: new Date().toISOString(),
                notes
            }
        });
        
        // Audit log
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'ACKNOWLEDGE_ALERT',
            resource: 'alert',
            resourceId: id,
            details: { notes },
            ip: req.ip
        });
        
        res.json({ 
            success: true, 
            data: result.rows[0],
            message: 'Alert acknowledged successfully'
        });
    } catch (err) {
        logger.error({ err: err.message, alert_id: id }, 'Acknowledge alert error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── BULK acknowledge alerts ─────────────────────────────────────────────────
router.post('/bulk/acknowledge', async (req, res) => {
    const { ids, notes } = req.body;
    
    if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ success: false, error: 'Invalid IDs array' });
    }
    
    try {
        const result = await tq(req, `
            UPDATE alerts 
            SET acknowledged = TRUE, 
                ack_by = $1, 
                ack_at = NOW(),
                ack_notes = COALESCE(ack_notes, '[]') || $2::jsonb
            WHERE id = ANY($3::uuid[])
            RETURNING id
        `, [req.user.id, notes ? JSON.stringify([notes]) : '[]', ids]);
        
        wsManager.broadcastToTenant(req.user.tenant_id, {
            event: 'alerts_bulk_acknowledged',
            data: { count: result.rows.length, ids, ack_by: req.user.username }
        });
        
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'BULK_ACKNOWLEDGE_ALERTS',
            resource: 'alert',
            details: { count: result.rows.length, ids },
            ip: req.ip
        });
        
        res.json({ 
            success: true, 
            acknowledged_count: result.rows.length,
            message: `${result.rows.length} alerts acknowledged`
        });
    } catch (err) {
        logger.error({ err: err.message }, 'Bulk acknowledge error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET alert statistics ────────────────────────────────────────────────────
router.get('/stats/summary', async (req, res) => {
    const { hours = 24 } = req.query;
    
    try {
        const result = await tq(req, `
            SELECT 
                COUNT(*) AS total,
                COUNT(CASE WHEN acknowledged = FALSE THEN 1 END) AS unacknowledged,
                COUNT(CASE WHEN severity = 'emergency' AND acknowledged = FALSE THEN 1 END) AS emergency_unacked,
                COUNT(CASE WHEN severity = 'critical' AND acknowledged = FALSE THEN 1 END) AS critical_unacked,
                COUNT(CASE WHEN severity = 'high' AND acknowledged = FALSE THEN 1 END) AS high_unacked,
                COUNT(CASE WHEN severity = 'medium' THEN 1 END) AS medium,
                COUNT(CASE WHEN severity = 'low' THEN 1 END) AS low,
                MAX(EXTRACT(EPOCH FROM (NOW() - detected_at))) / 60 AS oldest_unacked_minutes
            FROM alerts
            WHERE detected_at > NOW() - INTERVAL '${hours} hours'
        `);
        
        // Alerts by asset (top 5)
        const topAssets = await tq(req, `
            SELECT 
                a.name AS asset_name,
                COUNT(al.id) AS alert_count,
                COUNT(CASE WHEN al.acknowledged = FALSE THEN 1 END) AS unacked_count
            FROM alerts al
            JOIN assets a ON al.asset_id = a.id
            WHERE al.detected_at > NOW() - INTERVAL '24 hours'
            GROUP BY a.id, a.name
            ORDER BY alert_count DESC
            LIMIT 10
        `);
        
        res.json({
            success: true,
            data: {
                summary: result.rows[0],
                top_assets: topAssets.rows,
                period_hours: parseInt(hours)
            }
        });
    } catch (err) {
        logger.error({ err: err.message }, 'Alert stats error');
        res.status(500).json({ success: false, error: err.message });
    }
});

export default router;