#!/usr/bin/env node
/**
 * Cross-tenant isolation test.
 * Logs in as each seeded tenant admin and asserts each only sees their own data.
 * Requires backend on http://localhost:3001 with the shadow123 seed.
 */
const BASE = process.env.BASE_URL || 'http://localhost:3001';
const USERS = [
    { username: 'elal_admin',   tenantId: 1, label: 'EL AL'  },
    { username: 'israir_admin', tenantId: 2, label: 'Israir' },
    { username: 'arkia_admin',  tenantId: 3, label: 'Arkia'  },
];

async function login(username) {
    const r = await fetch(`${BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: 'shadow123' }),
    });
    const j = await r.json();
    if (!j.success) throw new Error(`login failed for ${username}: ${JSON.stringify(j)}`);
    return { token: j.accessToken, tenantId: j.user.tenant_id };
}

async function getJson(path, token) {
    const r = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } });
    return r.json();
}

function assert(cond, msg) {
    if (!cond) { console.error('  ✗', msg); process.exitCode = 1; }
    else       { console.log ('  ✓', msg); }
}

(async () => {
    for (const u of USERS) {
        console.log(`\n== ${u.label} (${u.username}) ==`);
        const { token, tenantId } = await login(u.username);
        assert(tenantId === u.tenantId, `token.tenant_id=${tenantId} matches seed=${u.tenantId}`);

        const assets  = (await getJson('/api/assets',  token)).data || [];
        const threats = (await getJson('/api/threats', token)).data || [];
        const alerts  = (await getJson('/api/alerts',  token)).data || [];

        console.log(`  assets=${assets.length} threats=${threats.length} alerts=${alerts.length}`);

        // Every asset must carry this tenant's ICAO prefix — any foreign prefix
        // means RLS leaked across tenants, regardless of absolute row counts.
        const prefix = { 1: '4XE', 2: '4XA', 3: '4XB' }[u.tenantId];
        const assetIcaos = assets.map(a => a.icao24).filter(Boolean);
        assert(assetIcaos.length > 0, `has at least one asset with icao24`);
        assert(assetIcaos.every(i => i.startsWith(prefix)),
               `every asset icao24 starts with ${prefix} (got: ${assetIcaos.join(',')})`);

        // Threat icao24 (when present) must also match this tenant's prefix.
        const threatIcaos = threats.map(t => t.icao24).filter(Boolean);
        assert(threatIcaos.every(i => i.startsWith(prefix)),
               `every threat icao24 starts with ${prefix} (got: ${threatIcaos.join(',') || '∅'})`);

        // Alerts must only reference assets we can see (i.e. this tenant's).
        const assetIdSet = new Set(assets.map(a => a.id));
        const foreignAlertAssets = alerts
            .map(a => a.asset_id)
            .filter(id => id != null && !assetIdSet.has(id));
        assert(foreignAlertAssets.length === 0,
               `no alert references a foreign asset (foreign: ${foreignAlertAssets.join(',') || '∅'})`);
    }
    console.log(process.exitCode ? '\n✗ ISOLATION BROKEN' : '\n✓ TENANT ISOLATION VERIFIED');
})().catch(e => { console.error(e); process.exit(1); });
