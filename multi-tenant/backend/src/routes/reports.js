import { Router } from 'express';
import { z } from 'zod';
import { db } from '../services/database.js';
import { authenticate } from '../middleware/auth.js';
import { auditLog } from '../services/audit.js';
import { logger } from '../utils/logger.js';

const router = Router();
router.use(authenticate);

// Helper for tenant queries
const tq = async (req, sql, params = []) => {
    return db.tenantQuery(req.user.tenant_id, sql, params);
};

// Validation schemas
const ExportReportSchema = z.object({
    format: z.enum(['json', 'csv', 'pdf']).default('json'),
    from: z.string().optional(),
    to: z.string().optional(),
    severity: z.string().optional(),
    threat_type: z.string().optional()
});

// ─── GET all attack reports (with filters) ───────────────────────────────────
router.get('/', async (req, res) => {
    const { 
        severity, threat_type, from, to, 
        asset_id, limit = 100, page = 1 
    } = req.query;
    
    const conditions = ['tenant_id = $1'];
    const params = [req.user.tenant_id];
    let paramIdx = 2;
    
    if (severity) {
        conditions.push(`severity = $${paramIdx++}`);
        params.push(severity);
    }
    if (threat_type) {
        conditions.push(`threat_type ILIKE $${paramIdx++}`);
        params.push(`%${threat_type}%`);
    }
    if (from) {
        conditions.push(`detected_at >= $${paramIdx++}`);
        params.push(new Date(from));
    }
    if (to) {
        conditions.push(`detected_at <= $${paramIdx++}`);
        params.push(new Date(to));
    }
    if (asset_id) {
        conditions.push(`asset_id = $${paramIdx++}`);
        params.push(asset_id);
    }
    
    const whereClause = conditions.join(' AND ');
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    try {
        const [reports, countResult] = await Promise.all([
            tq(req, `
                SELECT
                    threat_id,
                    threat_type,
                    severity,
                    description,
                    score,
                    mitre_technique,
                    threat_status,
                    detected_at,
                    resolved_at,
                    asset_id,
                    aircraft_name,
                    icao24,
                    callsign,
                    registration AS tail_number,
                    location,
                    current_threat_level,
                    protected AS is_protected,
                    latitude,
                    longitude,
                    altitude_ft,
                    speed_kts,
                    EXTRACT(EPOCH FROM (NOW() - detected_at)) / 3600 AS hours_ago
                FROM v_attack_reports
                WHERE ${whereClause}
                ORDER BY detected_at DESC
                LIMIT $${paramIdx++} OFFSET $${paramIdx++}
            `, [...params, parseInt(limit), offset]),
            tq(req, `SELECT COUNT(*)::INT AS total FROM v_attack_reports WHERE ${whereClause}`, params)
        ]);
        
        // Calculate summary statistics
        const summary = await tq(req, `
            SELECT 
                COUNT(*) AS total_attacks,
                COUNT(CASE WHEN severity IN ('critical', 'emergency') THEN 1 END) AS critical_attacks,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) AS high_attacks,
                COUNT(CASE WHEN threat_status = 'active' THEN 1 END) AS active_attacks,
                AVG(score) AS avg_score,
                COUNT(DISTINCT aircraft_name) AS affected_aircraft
            FROM v_attack_reports
            WHERE ${whereClause}
        `, params);
        
        res.json({
            success: true,
            data: reports.rows,
            summary: summary.rows[0],
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: countResult.rows[0].total,
                pages: Math.ceil(countResult.rows[0].total / parseInt(limit))
            },
            filters: { severity, threat_type, from, to, asset_id },
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        logger.error({ err: err.message }, 'Reports fetch error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET single report by threat ID ──────────────────────────────────────────
router.get('/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await tq(req, `
            SELECT 
                r.*,
                a.latitude,
                a.longitude,
                a.altitude_ft,
                a.speed_kts,
                a.heading,
                a.squawk,
                a.last_contact,
                a.metadata,
                (
                    SELECT json_agg(json_build_object(
                        'id', al.id,
                        'title', al.title,
                        'severity', al.severity,
                        'detected_at', al.detected_at,
                        'acknowledged', al.acknowledged
                    ))
                    FROM alerts al
                    WHERE al.threat_id = r.threat_id
                    ORDER BY al.detected_at DESC
                    LIMIT 10
                ) AS related_alerts
            FROM v_attack_reports r
            LEFT JOIN assets a ON r.asset_id = a.id
            WHERE r.tenant_id = $1 AND r.threat_id = $2::UUID
        `, [req.user.tenant_id, id]);
        
        if (!result.rows.length) {
            return res.status(404).json({ success: false, error: 'Report not found' });
        }
        
        // Get timeline of events for this attack
        const timeline = await tq(req, `
            SELECT 
                'threat_detected' AS event_type,
                detected_at AS event_time,
                'Threat detected' AS description
            FROM threats
            WHERE id = $1::UUID
            UNION ALL
            SELECT 
                'status_change' AS event_type,
                updated_at AS event_time,
                'Status changed to ' || status AS description
            FROM threats
            WHERE id = $1::UUID AND updated_at IS NOT NULL
            UNION ALL
            SELECT 
                'alert_created' AS event_type,
                detected_at AS event_time,
                'Alert: ' || title AS description
            FROM alerts
            WHERE threat_id = $1::UUID
            ORDER BY event_time ASC
        `, [id]);
        
        res.json({
            success: true,
            data: {
                ...result.rows[0],
                timeline: timeline.rows
            }
        });
    } catch (err) {
        logger.error({ err: err.message, report_id: id }, 'Report detail error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET report by ICAO24 (aircraft identifier) ──────────────────────────────
router.get('/aircraft/:icao24', async (req, res) => {
    const { icao24 } = req.params;
    const { limit = 50 } = req.query;
    
    try {
        const result = await tq(req, `
            SELECT 
                threat_id,
                threat_type,
                severity,
                description,
                score,
                detected_at,
                aircraft_name,
                location,
                current_threat_level,
                is_protected
            FROM v_attack_reports
            WHERE tenant_id = $1 AND icao24 = $2
            ORDER BY detected_at DESC
            LIMIT $3
        `, [req.user.tenant_id, icao24.toUpperCase(), parseInt(limit)]);
        
        const stats = await tq(req, `
            SELECT 
                COUNT(*) AS total_attacks,
                COUNT(CASE WHEN severity IN ('critical', 'emergency') THEN 1 END) AS critical_attacks,
                MAX(detected_at) AS last_attack
            FROM v_attack_reports
            WHERE tenant_id = $1 AND icao24 = $2
        `, [req.user.tenant_id, icao24.toUpperCase()]);
        
        res.json({
            success: true,
            data: result.rows,
            aircraft_icao: icao24,
            stats: stats.rows[0],
            count: result.rows.length
        });
    } catch (err) {
        logger.error({ err: err.message, icao24 }, 'Aircraft reports error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── EXPORT reports (CSV/JSON) ───────────────────────────────────────────────
router.get('/export/all', async (req, res) => {
    const validation = ExportReportSchema.safeParse(req.query);
    
    if (!validation.success) {
        return res.status(400).json({ success: false, error: validation.error.errors });
    }
    
    const { format, from, to, severity, threat_type } = validation.data;
    
    const conditions = ['tenant_id = $1'];
    const params = [req.user.tenant_id];
    let paramIdx = 2;
    
    if (from) {
        conditions.push(`detected_at >= $${paramIdx++}`);
        params.push(new Date(from));
    }
    if (to) {
        conditions.push(`detected_at <= $${paramIdx++}`);
        params.push(new Date(to));
    }
    if (severity) {
        conditions.push(`severity = $${paramIdx++}`);
        params.push(severity);
    }
    if (threat_type) {
        conditions.push(`threat_type ILIKE $${paramIdx++}`);
        params.push(`%${threat_type}%`);
    }
    
    const whereClause = conditions.join(' AND ');
    
    try {
        const result = await tq(req, `
            SELECT
                threat_id,
                threat_type,
                severity,
                description,
                score,
                mitre_technique,
                threat_status,
                detected_at,
                resolved_at,
                aircraft_name,
                icao24,
                registration AS tail_number,
                location,
                current_threat_level,
                protected AS is_protected
            FROM v_attack_reports
            WHERE ${whereClause}
            ORDER BY detected_at DESC
        `, params);
        
        if (format === 'csv') {
            // Generate CSV
            const headers = [
                'Threat ID', 'Type', 'Severity', 'Description', 'Score', 'MITRE',
                'Status', 'Detected At', 'Resolved At', 'Aircraft', 'ICAO24',
                'Tail Number', 'Location', 'Threat Level', 'Protected'
            ];
            
            const rows = result.rows.map(r => [
                r.threat_id,
                r.threat_type,
                r.severity,
                r.description || '',
                r.score,
                r.mitre_technique || '',
                r.threat_status,
                r.detected_at,
                r.resolved_at || '',
                r.aircraft_name || '',
                r.icao24 || '',
                r.tail_number || '',
                r.location || '',
                r.current_threat_level,
                r.is_protected ? 'Yes' : 'No'
            ]);
            
            const csvContent = [
                headers.join(','),
                ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
            ].join('\n');
            
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=attack_reports_${new Date().toISOString().slice(0,19)}.csv`);
            res.send(csvContent);
        } else {
            // JSON format
            res.json({
                success: true,
                data: result.rows,
                export_date: new Date().toISOString(),
                count: result.rows.length,
                filters: { from, to, severity, threat_type }
            });
        }
        
        // Audit log
        await auditLog({
            tenantId: req.user.tenant_id,
            userId: req.user.id,
            username: req.user.username,
            action: 'EXPORT_REPORTS',
            resource: 'report',
            details: { format, filters: { from, to, severity, threat_type }, count: result.rows.length },
            ip: req.ip
        });
        
    } catch (err) {
        logger.error({ err: err.message }, 'Export reports error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET attack statistics (dashboard summary) ───────────────────────────────
router.get('/stats/summary', async (req, res) => {
    const { days = 30 } = req.query;
    
    try {
        // Daily attack trend
        const dailyTrend = await tq(req, `
            SELECT 
                DATE_TRUNC('day', detected_at) AS day,
                COUNT(*) AS attacks,
                COUNT(CASE WHEN severity IN ('critical', 'emergency') THEN 1 END) AS critical_attacks,
                AVG(score) AS avg_score
            FROM v_attack_reports
            WHERE detected_at > NOW() - INTERVAL '${days} days'
            GROUP BY DATE_TRUNC('day', detected_at)
            ORDER BY day ASC
        `);
        
        // Attack types distribution
        const attackTypes = await tq(req, `
            SELECT 
                threat_type,
                COUNT(*) AS count,
                AVG(score) AS avg_score,
                MAX(score) AS max_score
            FROM v_attack_reports
            WHERE detected_at > NOW() - INTERVAL '30 days'
            GROUP BY threat_type
            ORDER BY count DESC
            LIMIT 15
        `);
        
        // Top affected aircraft
        const topAircraft = await tq(req, `
            SELECT 
                aircraft_name,
                icao24,
                COUNT(*) AS attack_count,
                MAX(score) AS max_score,
                COUNT(CASE WHEN severity IN ('critical', 'emergency') THEN 1 END) AS critical_count
            FROM v_attack_reports
            WHERE detected_at > NOW() - INTERVAL '30 days'
                AND aircraft_name IS NOT NULL
            GROUP BY aircraft_name, icao24
            ORDER BY attack_count DESC
            LIMIT 10
        `);
        
        // MITRE technique distribution
        const mitreDistribution = await tq(req, `
            SELECT 
                mitre_technique,
                COUNT(*) AS count
            FROM v_attack_reports
            WHERE mitre_technique IS NOT NULL
                AND detected_at > NOW() - INTERVAL '30 days'
            GROUP BY mitre_technique
            ORDER BY count DESC
            LIMIT 10
        `);
        
        res.json({
            success: true,
            data: {
                daily_trend: dailyTrend.rows,
                attack_types: attackTypes.rows,
                top_affected_aircraft: topAircraft.rows,
                mitre_distribution: mitreDistribution.rows,
                period_days: parseInt(days)
            }
        });
    } catch (err) {
        logger.error({ err: err.message }, 'Report stats error');
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── GET monthly report summary ──────────────────────────────────────────────
router.get('/monthly/:year/:month', async (req, res) => {
    const { year, month } = req.params;
    const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
    const endDate = new Date(parseInt(year), parseInt(month), 0);
    
    try {
        const result = await tq(req, `
            SELECT 
                COUNT(*) AS total_attacks,
                COUNT(DISTINCT threat_id) AS unique_attacks,
                COUNT(CASE WHEN severity IN ('critical', 'emergency') THEN 1 END) AS critical_attacks,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) AS high_attacks,
                COUNT(DISTINCT aircraft_name) AS affected_aircraft,
                AVG(score) AS avg_score,
                MIN(detected_at) AS first_attack,
                MAX(detected_at) AS last_attack
            FROM v_attack_reports
            WHERE detected_at BETWEEN $1 AND $2
        `, [startDate, endDate]);
        
        const dailyBreakdown = await tq(req, `
            SELECT 
                DATE_TRUNC('day', detected_at) AS day,
                COUNT(*) AS attacks
            FROM v_attack_reports
            WHERE detected_at BETWEEN $1 AND $2
            GROUP BY DATE_TRUNC('day', detected_at)
            ORDER BY day ASC
        `, [startDate, endDate]);
        
        res.json({
            success: true,
            data: {
                year: parseInt(year),
                month: parseInt(month),
                summary: result.rows[0],
                daily_breakdown: dailyBreakdown.rows
            }
        });
    } catch (err) {
        logger.error({ err: err.message, year, month }, 'Monthly report error');
        res.status(500).json({ success: false, error: err.message });
    }
});

export default router;