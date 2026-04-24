/**
 * Attack lifecycle manager.
 *
 * Responsibilities:
 *   1. Dedupe: when a new sensor threat arrives for the same
 *      (tenant, asset/icao24, threat_type) that's still active, bump the
 *      existing row's last_seen + hit_count instead of creating a duplicate.
 *   2. Sweeper: every SWEEP_INTERVAL_MS, mark any active threat whose
 *      last_seen is older than ACTIVE_TTL_MS as resolved and demote the
 *      associated asset's threat_level back to safe when no other active
 *      threats remain on it.
 *   3. Emit WS events for every state transition so the UI can update in
 *      real-time: `threat:new`, `threat:update`, `threat:resolved`,
 *      `asset:threat_level`.
 */
import { db } from './database.js';
import { logger } from '../utils/logger.js';

const ACTIVE_TTL_MS     = Number(process.env.THREAT_ACTIVE_TTL_MS   || 90_000);
const SWEEP_INTERVAL_MS = Number(process.env.THREAT_SWEEP_INTERVAL_MS || 15_000);

function levelFromSeverity(severity) {
    if (severity === 'critical') return 'under_attack';
    if (severity === 'high')     return 'critical';
    if (severity === 'medium')   return 'warning';
    return 'safe';
}

/**
 * Upsert an active threat. If an active row exists for the same
 * tenant/asset/threat_type within ACTIVE_TTL_MS, extend it; otherwise insert.
 * Returns { threat, created } so the caller can emit the right WS event.
 */
export async function upsertActiveThreat(tenantId, {
    threat_type, severity, source_ip, dest_ip, icao24, asset_id,
    score, description, raw_features, mitre_technique,
}) {
    const dedupeSql = `
        SELECT id FROM threats
        WHERE status = 'active'
          AND threat_type = $1
          AND (
              ($2::integer IS NOT NULL AND asset_id = $2) OR
              ($3::text    IS NOT NULL AND icao24 = $3)   OR
              ($2::integer IS NULL AND $3::text IS NULL AND source_ip = $4)
          )
          AND last_seen > NOW() - ($5 || ' milliseconds')::interval
        ORDER BY last_seen DESC LIMIT 1
    `;
    const existing = await db.tenantQuery(tenantId, dedupeSql, [
        threat_type, asset_id ?? null, icao24 ?? null, source_ip ?? null, ACTIVE_TTL_MS,
    ]);

    if (existing.rows.length) {
        const id = existing.rows[0].id;
        const updated = await db.tenantQuery(
            tenantId,
            `UPDATE threats
             SET last_seen = NOW(),
                 hit_count = hit_count + 1,
                 score = GREATEST(score, $2),
                 severity = CASE
                     WHEN $3 = 'critical' THEN 'critical'
                     WHEN severity = 'critical' THEN severity
                     WHEN $3 = 'high' THEN 'high'
                     ELSE severity
                 END
             WHERE id = $1 RETURNING *`,
            [id, score ?? 0, severity],
        );
        await syncAssetThreatLevel(tenantId, asset_id, icao24);
        return { threat: updated.rows[0], created: false };
    }

    const inserted = await db.tenantQuery(
        tenantId,
        `INSERT INTO threats (
            tenant_id, threat_type, severity, source_ip, dest_ip, icao24, asset_id,
            score, description, raw_features, mitre_technique,
            status, detected_at, last_seen, hit_count
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'active',NOW(),NOW(),1)
         RETURNING *`,
        [
            tenantId, threat_type, severity, source_ip ?? null, dest_ip ?? null,
            icao24 ?? null, asset_id ?? null, score ?? 0, description ?? null,
            raw_features ? JSON.stringify(raw_features) : null,
            mitre_technique ?? null,
        ],
    );
    await syncAssetThreatLevel(tenantId, asset_id, icao24);
    return { threat: inserted.rows[0], created: true };
}

/**
 * Recalculate an asset's `threat_level` based on its currently-active threats.
 * Called after any lifecycle transition. Emits asset:threat_level if changed.
 */
export async function syncAssetThreatLevel(tenantId, assetId, icao24, io) {
    const where = assetId
        ? 'id = $1'
        : (icao24 ? 'icao24 = $1' : null);
    if (!where) return;
    const keyVal = assetId ?? icao24;

    const assetRow = await db.tenantQuery(tenantId,
        `SELECT id, threat_level FROM assets WHERE ${where} LIMIT 1`, [keyVal]);
    if (!assetRow.rows.length) return;
    const { id: aId, threat_level: currentLevel } = assetRow.rows[0];

    const activeRow = await db.tenantQuery(tenantId, `
        SELECT severity FROM threats
        WHERE status='active' AND (asset_id = $1 OR (icao24 IS NOT NULL AND icao24 = $2))
        ORDER BY CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high'     THEN 2
            WHEN 'medium'   THEN 3
            ELSE 4 END
        LIMIT 1`, [aId, icao24 ?? null]);

    const nextLevel = activeRow.rows.length
        ? levelFromSeverity(activeRow.rows[0].severity)
        : 'safe';

    if (currentLevel !== nextLevel) {
        await db.tenantQuery(tenantId,
            `UPDATE assets SET threat_level = $1 WHERE id = $2`, [nextLevel, aId]);
        if (io) {
            io.to(`tenant:${tenantId}`).emit('asset:threat_level', {
                asset_id: aId, icao24, threat_level: nextLevel,
            });
        }
    }
}

/**
 * Periodic sweeper. Must run as a system role that can see all tenants,
 * so we bypass tenantQuery here and use db.query with a dedicated role.
 * We use superadmin GUC so superadmin_* policies allow access.
 */
export function startSweeper(io) {
    const tick = async () => {
        try {
            const client = await db.pool.connect();
            try {
                await client.query('BEGIN');
                await client.query(
                    `SELECT set_config('app.role', 'superadmin', true)`);
                const stale = await client.query(`
                    UPDATE threats
                    SET status = 'resolved', resolved_at = NOW()
                    WHERE status = 'active'
                      AND last_seen < NOW() - ($1 || ' milliseconds')::interval
                    RETURNING id, tenant_id, asset_id, icao24, threat_type, severity, resolved_at
                `, [ACTIVE_TTL_MS]);
                await client.query('COMMIT');

                for (const row of stale.rows) {
                    io.to(`tenant:${row.tenant_id}`).emit('threat:resolved', row);
                    await syncAssetThreatLevel(row.tenant_id, row.asset_id, row.icao24, io);
                }
                if (stale.rowCount > 0) {
                    logger.info({ resolved: stale.rowCount }, 'Auto-resolved stale threats');
                }
            } catch (err) {
                try { await client.query('ROLLBACK'); } catch { /* ignore */ }
                throw err;
            } finally {
                client.release();
            }
        } catch (err) {
            logger.error({ err: err.message }, 'Threat sweeper tick failed');
        }
    };
    const handle = setInterval(tick, SWEEP_INTERVAL_MS);
    logger.info({ ACTIVE_TTL_MS, SWEEP_INTERVAL_MS }, 'Threat lifecycle sweeper started');
    return () => clearInterval(handle);
}
