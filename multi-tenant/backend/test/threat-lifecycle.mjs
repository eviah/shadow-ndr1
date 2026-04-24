#!/usr/bin/env node
/**
 * Attack lifecycle test.
 *   1. Fire 3 rapid sensor POSTs for the same EL AL aircraft → expect ONE threat
 *      row with hit_count=3 (dedupe).
 *   2. Confirm the asset's threat_level flips to under_attack/critical.
 *   3. Wait until TTL expires (or manually fast-forward via DB) and confirm
 *      the threat auto-resolves and asset reverts to 'safe'.
 *
 * Requires: backend running with sensor endpoint open, ACTIVE_TTL_MS=90s default.
 * To run it quickly we DB-age the row's last_seen forward and trigger the sweeper.
 */
const BASE = process.env.BASE_URL || 'http://localhost:3001';
const ICAO = '4XEDF'; // EL AL aircraft from seed

function assert(cond, msg) {
    if (!cond) { console.error('  ✗', msg); process.exitCode = 1; }
    else       { console.log ('  ✓', msg); }
}

async function login(username) {
    const r = await fetch(`${BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: 'shadow123' }),
    });
    const j = await r.json();
    if (!j.success) throw new Error(`login failed: ${JSON.stringify(j)}`);
    return j.accessToken;
}

async function fireAttack(i) {
    const body = {
        protocol: 'icmp',
        timestamp: new Date().toISOString(),
        flow_id: `life-${i}`,
        src_ip: '203.0.113.10',
        dst_ip: '10.0.0.1',
        src_port: 0,
        dst_port: 0,
        threat_level: 'critical',
        details: { icao24: ICAO, attempt: i },
        icao24: ICAO,
    };
    const r = await fetch(`${BASE}/api/sensor/data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return r.json();
}

(async () => {
    const token = await login('elal_admin');
    const auth = { Authorization: `Bearer ${token}` };

    console.log('== DEDUPE ==');
    const r1 = await fireAttack(1);
    const r2 = await fireAttack(2);
    const r3 = await fireAttack(3);
    assert(r1.success && r2.success && r3.success, 'all 3 sensor posts accepted');
    const ids = new Set([r1.threat.id, r2.threat.id, r3.threat.id]);
    assert(ids.size === 1, `all 3 POSTs collapse to one threat row (ids=${[...ids].join(',')})`);
    assert(r3.threat.hit_count >= 3, `hit_count bumped (got ${r3.threat.hit_count})`);

    console.log('\n== ASSET THREAT LEVEL ==');
    // give the async syncAssetThreatLevel a tick
    await new Promise(r => setTimeout(r, 500));
    const assetsResp = await fetch(`${BASE}/api/assets`, { headers: auth }).then(r => r.json());
    const target = (assetsResp.data || []).find(a => a.icao24 === ICAO);
    assert(target, `asset ${ICAO} visible to elal_admin`);
    assert(['under_attack','critical'].includes(target?.threat_level),
           `asset.threat_level escalated (got ${target?.threat_level})`);

    console.log('\n== AUTO-RESOLVE ==');
    // Fast-forward: age last_seen past TTL so sweeper resolves on next tick
    console.log('  ...aging last_seen and waiting for next sweeper tick (≤15s)');
    const { execSync } = await import('node:child_process');
    execSync(
      `docker exec shadow-postgres psql -U shadow -d shadow_ndr_mt -c ` +
      `"UPDATE threats SET last_seen = NOW() - INTERVAL '5 minutes' WHERE id = '${r3.threat.id}'"`,
      { stdio: 'pipe' },
    );
    await new Promise(r => setTimeout(r, 17_000));

    const threatsResp = await fetch(`${BASE}/api/threats`, { headers: auth }).then(r => r.json());
    const after = (threatsResp.data || []).find(t => t.id === r3.threat.id);
    assert(after, 'threat row still present after resolve');
    assert(after?.status === 'resolved', `status=resolved (got ${after?.status})`);
    assert(after?.resolved_at, `resolved_at set (got ${after?.resolved_at})`);

    const assetsAfter = await fetch(`${BASE}/api/assets`, { headers: auth }).then(r => r.json());
    const targetAfter = (assetsAfter.data || []).find(a => a.icao24 === ICAO);
    assert(targetAfter?.threat_level === 'safe',
           `asset.threat_level reverted to safe (got ${targetAfter?.threat_level})`);

    console.log(process.exitCode ? '\n✗ LIFECYCLE BROKEN' : '\n✓ LIFECYCLE VERIFIED');
})().catch(e => { console.error(e); process.exit(1); });
