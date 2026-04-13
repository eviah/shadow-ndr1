import { Router } from 'express';
import { db } from '../services/database.js';
import { authenticate } from '../middleware/auth.js';
import { cached, invalidate } from '../services/redis.js';
import { logger } from '../utils/logger.js';

const router = Router();
router.use(authenticate);

const tq = async (req, sql, params = []) => {
    return db.tenantQuery(req.user.tenant_id, sql, params);
};

async function fetchDashboardData(tenantId, req) {
    const threatsResult = await tq(req, `
        SELECT 
            COUNT(*)::INT AS total,
            COUNT(CASE WHEN severity IN ('critical','emergency') THEN 1 END)::INT AS critical,
            COUNT(CASE WHEN status = 'active' THEN 1 END)::INT AS active,
            COALESCE(AVG(score), 0)::FLOAT AS avg_score
        FROM threats 
        WHERE detected_at > NOW() - INTERVAL '24 hours'
    `);
    
    const assetsResult = await tq(req, `
        SELECT 
            COUNT(*)::INT AS total,
            COUNT(CASE WHEN status = 'active' THEN 1 END)::INT AS active,
            COUNT(CASE WHEN threat_level = 'under_attack' THEN 1 END)::INT AS under_attack
        FROM assets
    `);
    
    const alertsResult = await tq(req, `
        SELECT 
            COUNT(*)::INT AS total,
            COUNT(CASE WHEN acknowledged = FALSE THEN 1 END)::INT AS unacknowledged
        FROM alerts
        WHERE detected_at > NOW() - INTERVAL '6 hours'
    `);
    
    const topAttacks = await tq(req, `
        SELECT threat_type, COUNT(*)::INT AS count
        FROM threats 
        WHERE detected_at > NOW() - INTERVAL '24 hours'
        GROUP BY threat_type 
        ORDER BY count DESC 
        LIMIT 8
    `);
    
    const riskTop = await tq(req, `
        SELECT entity_name, risk_score, threat_types
        FROM risk_scores 
        ORDER BY risk_score DESC 
        LIMIT 5
    `);
    
    const recentAlerts = await tq(req, `
        SELECT al.id, al.title, al.severity, al.detected_at, a.name AS aircraft_name
        FROM alerts al
        LEFT JOIN assets a ON al.asset_id = a.id
        ORDER BY al.detected_at DESC 
        LIMIT 15
    `);
    
    const timeline = await tq(req, `
        SELECT 
            DATE_TRUNC('hour', detected_at) AS hour,
            COUNT(*)::INT AS count,
            COALESCE(AVG(score), 0)::FLOAT AS avg_score
        FROM threats 
        WHERE detected_at > NOW() - INTERVAL '12 hours'
        GROUP BY DATE_TRUNC('hour', detected_at)
        ORDER BY hour ASC
    `);
    
    return {
        threats: threatsResult.rows[0] || { total: 0, critical: 0, active: 0, avg_score: 0 },
        assets: assetsResult.rows[0] || { total: 0, active: 0, under_attack: 0 },
        alerts: alertsResult.rows[0] || { total: 0, unacknowledged: 0 },
        topAttacks: topAttacks.rows,
        riskTop: riskTop.rows,
        recentAlerts: recentAlerts.rows,
        timeline: timeline.rows,
        generatedAt: new Date().toISOString()
    };
}

router.get('/', async (req, res) => {
    try {
        const cacheKey = `dash:${req.user.tenant_id}`;
        const data = await cached(cacheKey, 30, () => fetchDashboardData(req.user.tenant_id, req));
        res.json({ success: true, data });
    } catch (err) {
        logger.error({ err: err.message }, 'Dashboard error');
        res.status(500).json({ success: false, error: err.message });
    }
});

export default router;