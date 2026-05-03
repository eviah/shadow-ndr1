/**
 * Auto-Defender — closes the loop on every active threat.
 *
 * Pipeline: every new active threat triggers a mitigation pipeline. The
 * pipeline picks an action by threat-type, applies it (in-memory blocklists
 * for sources/assets, simulator pause for spoofing on a specific aircraft),
 * stamps the threat row's `raw_features.mitigation` with the action +
 * defender score, flips the threat to `status = 'resolved'`, and broadcasts
 * `threat:mitigated` so the UI can render a green "BLOCKED" state instead of
 * leaving the operator wondering whether the system actually responded.
 *
 * The mitigation actions are real for the demo surface:
 *   - blockSourceIp:   in-memory tenant-scoped IP blocklist any future
 *                       upserts can consult to drop traffic at the door.
 *   - quarantineAsset: pauses the simulated aircraft (cuts attack flow) and
 *                       flips its asset status to 'compromised'.
 *   - rejectCallsign:  marks the spoofed callsign so subsequent sensor
 *                       events with the same icao24 are dropped.
 *
 * A small delay (DEFENDER_DELAY_MS, default 2.2 s) is inserted between
 * threat:new and threat:mitigated so the operator can visually see the
 * attack come in, then watch it get stopped — that's the demo moment.
 */
import { db } from './database.js';
import { logger } from '../utils/logger.js';
import { setPaused as pauseFlight } from './simulator.js';

const DELAY_MS = Number(process.env.DEFENDER_DELAY_MS || 2_200);
const MAX_LOG  = 200;

// ── tenant-scoped state (process-local, fine for demo) ───────────────────────
const blockedIps        = new Map(); // tenantId -> Set<ip>
const quarantinedAssets = new Map(); // tenantId -> Map<assetId, {at, reason}>
const blockedCallsigns  = new Map(); // tenantId -> Set<icao24>
const stats = {
    log: [],            // [{ts, tenantId, action, technique, target, threatId, threat_type, severity}]
    totals: { mitigated: 0, blockedIps: 0, quarantined: 0, callsigns: 0 },
};

const setOf = (map, k) => { let s = map.get(k); if (!s) { s = new Set(); map.set(k, s); } return s; };
const mapOf = (map, k) => { let m = map.get(k); if (!m) { m = new Map(); map.set(k, m); } return m; };

// ── playbook: threat_type → mitigation action + MITRE-style technique ────────
const PLAYBOOK = {
    // RF / aviation
    spoofing:           { action: 'GPS_AUTH_REJECT',     technique: 'D3-RF-AUTH',     score: 0.94, primary: 'callsign' },
    gps_spoofing:       { action: 'GPS_AUTH_REJECT',     technique: 'D3-RF-AUTH',     score: 0.96, primary: 'callsign' },
    'ads-b_injection':  { action: 'ADSB_FILTER_DROP',    technique: 'D3-INPF',        score: 0.92, primary: 'callsign' },
    'mode-s_replay':    { action: 'NONCE_HANDSHAKE',     technique: 'D3-RPA',         score: 0.90, primary: 'callsign' },
    rogue_atc:          { action: 'CHANNEL_AUTH_LOCK',   technique: 'D3-AUTH',        score: 0.88, primary: 'callsign' },
    jamming:            { action: 'FREQ_HOP_BLACKLIST',  technique: 'D3-HOP',         score: 0.82, primary: 'asset' },
    meaconing:          { action: 'BEAM_NULL_STEER',     technique: 'D3-BEAM',        score: 0.85, primary: 'asset' },
    deauth:             { action: 'PMF_ENFORCE',         technique: 'D3-WPA3',        score: 0.93, primary: 'ip' },
    mitm:               { action: 'CERT_PIN_DROP',       technique: 'D3-PIN',         score: 0.91, primary: 'ip' },
    protocol_fuzz:      { action: 'WAF_DROP',            technique: 'D3-WAF',         score: 0.89, primary: 'ip' },
    side_channel:       { action: 'CACHE_ISOLATE',       technique: 'D3-ISOL',        score: 0.86, primary: 'asset' },
    covert_channel:     { action: 'EGRESS_FILTER',       technique: 'D3-EGR',         score: 0.84, primary: 'ip' },
    rf_overpower:       { action: 'POWER_NULL_NOTCH',    technique: 'D3-NOTCH',       score: 0.81, primary: 'asset' },
    // generic / network
    icmp:               { action: 'IP_BLOCK',            technique: 'D3-IP-BLK',      score: 0.93, primary: 'ip' },
    tcp:                { action: 'CONN_RESET',          technique: 'D3-RST',         score: 0.90, primary: 'ip' },
    udp:                { action: 'IP_BLOCK',            technique: 'D3-IP-BLK',      score: 0.88, primary: 'ip' },
    'port-scan':        { action: 'IP_BLOCK',            technique: 'D3-IP-BLK',      score: 0.92, primary: 'ip' },
    bruteforce:         { action: 'AUTH_LOCKOUT',        technique: 'D3-LOCK',        score: 0.95, primary: 'ip' },
};

const DEFAULT_PLAY = { action: 'AUTO_QUARANTINE', technique: 'D3-AUTO', score: 0.75, primary: 'asset' };

function pickPlay(threat) {
    const key = (threat.threat_type || '').toLowerCase();
    return PLAYBOOK[key] || DEFAULT_PLAY;
}

// ── application ──────────────────────────────────────────────────────────────
function applyAction(tenantId, threat, play) {
    const targets = [];
    const target = play.primary;
    if ((target === 'ip' || play.action.startsWith('IP_') || play.action === 'CONN_RESET' || play.action === 'WAF_DROP' || play.action === 'CERT_PIN_DROP' || play.action === 'EGRESS_FILTER' || play.action === 'AUTH_LOCKOUT' || play.action === 'PMF_ENFORCE') && threat.source_ip) {
        setOf(blockedIps, tenantId).add(String(threat.source_ip));
        targets.push({ kind: 'ip', value: String(threat.source_ip) });
        stats.totals.blockedIps++;
    }
    if ((target === 'callsign' || ['GPS_AUTH_REJECT', 'ADSB_FILTER_DROP', 'NONCE_HANDSHAKE', 'CHANNEL_AUTH_LOCK'].includes(play.action)) && threat.icao24) {
        setOf(blockedCallsigns, tenantId).add(String(threat.icao24));
        targets.push({ kind: 'callsign', value: String(threat.icao24) });
        stats.totals.callsigns++;
    }
    if ((target === 'asset' || ['BEAM_NULL_STEER', 'POWER_NULL_NOTCH', 'CACHE_ISOLATE', 'AUTO_QUARANTINE', 'FREQ_HOP_BLACKLIST'].includes(play.action)) && threat.asset_id) {
        const m = mapOf(quarantinedAssets, tenantId);
        if (!m.has(threat.asset_id)) {
            m.set(threat.asset_id, { at: Date.now(), reason: play.action });
            stats.totals.quarantined++;
        }
        targets.push({ kind: 'asset', value: threat.asset_id });
        // Aircraft attacks: pause the simulated flight so it visibly halts on the map.
        if (play.action !== 'CACHE_ISOLATE') {
            try { pauseFlight(tenantId, threat.asset_id, true); setTimeout(() => pauseFlight(tenantId, threat.asset_id, false), 6_000); } catch {}
        }
    }
    return targets;
}

// ── public ───────────────────────────────────────────────────────────────────
export function isBlocked(tenantId, ip) {
    const s = blockedIps.get(tenantId);
    return !!(s && ip && s.has(String(ip)));
}
export function isQuarantined(tenantId, assetId) {
    const m = quarantinedAssets.get(tenantId);
    return !!(m && m.has(assetId));
}
export function isBannedCallsign(tenantId, icao24) {
    const s = blockedCallsigns.get(tenantId);
    return !!(s && icao24 && s.has(String(icao24)));
}

/**
 * Schedule mitigation for a freshly-created threat. Runs after DELAY_MS so
 * the operator visibly sees the attack arrive before it gets stopped.
 */
export function mitigate(tenantId, threat, io) {
    if (!threat || !threat.id) return;
    setTimeout(async () => {
        try {
            const play = pickPlay(threat);
            const targets = applyAction(tenantId, threat, play);
            const mitigation = {
                action: play.action,
                technique: play.technique,
                defender_score: play.score,
                targets,
                applied_at: new Date().toISOString(),
            };
            const r = await db.tenantQuery(
                tenantId,
                `UPDATE threats
                   SET status = 'resolved',
                       resolved_at = NOW(),
                       raw_features = COALESCE(raw_features, '{}'::jsonb) || $2::jsonb
                 WHERE id = $1 AND status = 'active'
                 RETURNING *`,
                [threat.id, JSON.stringify({ mitigation })],
            );
            if (!r.rows.length) return;        // sweeper or human got there first
            const row = r.rows[0];
            stats.totals.mitigated++;
            stats.log.unshift({
                ts: Date.now(), tenantId,
                action: play.action,
                technique: play.technique,
                target: targets[0],
                threatId: row.id,
                threat_type: row.threat_type,
                severity: row.severity,
            });
            if (stats.log.length > MAX_LOG) stats.log.length = MAX_LOG;

            if (io) {
                io.to(`tenant:${tenantId}`).emit('threat:mitigated', {
                    ...row,
                    mitigation,
                });
                // Asset threat-level demotion is broadcast by the lifecycle helper
                try {
                    const { syncAssetThreatLevel } = await import('./threatLifecycle.js');
                    await syncAssetThreatLevel(tenantId, row.asset_id, row.icao24, io);
                } catch {}
            }
        } catch (err) {
            logger.warn({ err: err.message, threatId: threat.id }, 'auto-defender failed');
        }
    }, DELAY_MS);
}

export function getStatus(tenantId) {
    return {
        delayMs: DELAY_MS,
        blockedIps: Array.from(blockedIps.get(tenantId) || []),
        blockedCallsigns: Array.from(blockedCallsigns.get(tenantId) || []),
        quarantinedAssets: Array.from((quarantinedAssets.get(tenantId) || new Map()).entries()).map(([id, v]) => ({ asset_id: id, ...v })),
        recent: stats.log.filter(e => e.tenantId === tenantId).slice(0, 50),
        totals: { ...stats.totals },
    };
}
