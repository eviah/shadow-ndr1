/**
 * Pre-Crime Forecaster
 *
 * Two predictions, fused into one stream:
 *
 * 1. Position-60: where every live aircraft will be 60 seconds from now,
 *    derived from heading/speed using great-circle dead-reckoning. Emitted
 *    as `forecast:asset` with `(asset_id, lat, lon, alt, heading, eta_s)`.
 *
 * 2. Hotspot heatmap: a kernel-density estimate over recent active threats
 *    weighted by recency × severity. The output is a small grid of {lat, lon,
 *    intensity 0..1, dominant_type} cells covering the operational area, plus
 *    a list of "hot zones" where any aircraft's 60s projection enters a
 *    high-intensity cell — those are the pre-crime hits.
 *
 * Emits `forecast:tick` once per second so the UI can ghost-trail planes
 * and overlay the heatmap without tearing.
 */
import { logger } from '../utils/logger.js';
import { db } from './database.js';
import { listFlights } from './simulator.js';

const TICK_MS = Number(process.env.FORECAST_TICK_MS || 1000);
const HORIZON_S = Number(process.env.FORECAST_HORIZON_S || 60);
const GRID_STEP_DEG = Number(process.env.FORECAST_GRID_STEP || 0.5);
const RECENCY_HALF_LIFE_S = 120;

const SEV_W = { critical: 1.0, high: 0.7, medium: 0.4, low: 0.2, emergency: 1.2 };

// ── Great-circle dead-reckoning ───────────────────────────────────────────────
const toRad = (d) => d * Math.PI / 180;
const toDeg = (r) => r * 180 / Math.PI;
const KT_TO_M_S = 0.514444;
const EARTH_M = 6371008.8;

function projectPosition(lat, lon, headingDeg, speedKts, etaSec) {
    if (lat == null || lon == null || speedKts == null) return null;
    const distM = speedKts * KT_TO_M_S * etaSec;
    const angDist = distM / EARTH_M;
    const φ1 = toRad(lat), λ1 = toRad(lon), θ = toRad(headingDeg || 0);
    const φ2 = Math.asin(Math.sin(φ1) * Math.cos(angDist) + Math.cos(φ1) * Math.sin(angDist) * Math.cos(θ));
    const λ2 = λ1 + Math.atan2(Math.sin(θ) * Math.sin(angDist) * Math.cos(φ1), Math.cos(angDist) - Math.sin(φ1) * Math.sin(φ2));
    return { lat: toDeg(φ2), lon: ((toDeg(λ2) + 540) % 360) - 180 };
}

// ── Hotspot KDE ───────────────────────────────────────────────────────────────
async function recentThreatsForKDE(tenantId) {
    try {
        const r = await db.tenantQuery(tenantId, `
            SELECT t.id, t.severity, t.threat_type, t.created_at,
                   COALESCE(a.latitude, 0)  AS lat,
                   COALESCE(a.longitude, 0) AS lon
            FROM threats t
            LEFT JOIN assets a ON a.id = t.asset_id
            WHERE t.created_at > NOW() - INTERVAL '15 minutes'
            ORDER BY t.created_at DESC
            LIMIT 200
        `);
        return r.rows.filter(r => r.lat || r.lon);
    } catch {
        return [];
    }
}

function buildHeatmap(threats, now) {
    if (!threats.length) return { cells: [], dominantType: null };
    let minLat = +90, maxLat = -90, minLon = +180, maxLon = -180;
    for (const t of threats) {
        if (t.lat < minLat) minLat = t.lat;
        if (t.lat > maxLat) maxLat = t.lat;
        if (t.lon < minLon) minLon = t.lon;
        if (t.lon > maxLon) maxLon = t.lon;
    }
    minLat = Math.floor(minLat / GRID_STEP_DEG) * GRID_STEP_DEG - GRID_STEP_DEG;
    maxLat = Math.ceil(maxLat / GRID_STEP_DEG) * GRID_STEP_DEG + GRID_STEP_DEG;
    minLon = Math.floor(minLon / GRID_STEP_DEG) * GRID_STEP_DEG - GRID_STEP_DEG;
    maxLon = Math.ceil(maxLon / GRID_STEP_DEG) * GRID_STEP_DEG + GRID_STEP_DEG;

    const cells = new Map();
    const typeCount = new Map();
    for (const th of threats) {
        const ageS = (now - new Date(th.created_at).getTime()) / 1000;
        const recency = Math.exp(-ageS / RECENCY_HALF_LIFE_S);
        const sev = SEV_W[th.severity] ?? 0.3;
        const w = recency * sev;
        // Spread weight over a 3×3 neighborhood (Gaussian kernel approximation)
        for (let dy = -1; dy <= 1; dy++) {
            for (let dx = -1; dx <= 1; dx++) {
                const fall = Math.exp(-(dx * dx + dy * dy) / 2);
                const cy = Math.round(th.lat / GRID_STEP_DEG) + dy;
                const cx = Math.round(th.lon / GRID_STEP_DEG) + dx;
                const key = `${cy}|${cx}`;
                cells.set(key, (cells.get(key) || 0) + w * fall);
            }
        }
        typeCount.set(th.threat_type, (typeCount.get(th.threat_type) || 0) + w);
    }
    let max = 0;
    for (const v of cells.values()) if (v > max) max = v;
    const out = [];
    for (const [k, v] of cells.entries()) {
        const [cy, cx] = k.split('|').map(Number);
        out.push({
            lat: cy * GRID_STEP_DEG,
            lon: cx * GRID_STEP_DEG,
            intensity: max > 0 ? +(v / max).toFixed(3) : 0,
        });
    }
    out.sort((a, b) => b.intensity - a.intensity);
    let dom = null, domW = 0;
    for (const [t, w] of typeCount.entries()) if (w > domW) { domW = w; dom = t; }
    return { cells: out.slice(0, 80), dominantType: dom };
}

// ── Per-tick build for one tenant ─────────────────────────────────────────────
async function tenantForecast(tenantId, now) {
    const flights = listFlights(tenantId);
    const assets = flights.map(f => ({
        asset_id: f.asset_id, callsign: f.callsign, icao24: f.icao24,
        lat: f.lat, lon: f.lon, alt: f.altitude_ft, heading: f.heading, speed: f.speed_kts,
        from: f.from, to: f.to,
        forecast: projectPosition(f.lat, f.lon, f.heading, f.speed_kts, HORIZON_S),
    }));

    const threats = await recentThreatsForKDE(tenantId);
    const { cells, dominantType } = buildHeatmap(threats, now);

    // Cross-reference: which projected positions enter a high-intensity cell?
    const HIGH = 0.55;
    const hotZones = [];
    const cellLookup = new Map();
    for (const c of cells) cellLookup.set(`${Math.round(c.lat / GRID_STEP_DEG)}|${Math.round(c.lon / GRID_STEP_DEG)}`, c);
    for (const a of assets) {
        if (!a.forecast) continue;
        const key = `${Math.round(a.forecast.lat / GRID_STEP_DEG)}|${Math.round(a.forecast.lon / GRID_STEP_DEG)}`;
        const c = cellLookup.get(key);
        if (c && c.intensity >= HIGH) {
            hotZones.push({
                asset_id: a.asset_id, callsign: a.callsign, icao24: a.icao24,
                forecast: a.forecast, intensity: c.intensity, dominantType,
                eta_s: HORIZON_S,
            });
        }
    }

    return { assets, cells, dominantType, hotZones, horizon_s: HORIZON_S, ts: now };
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────
const state = { running: false, tickHandle: null, ioRef: null, latest: new Map() };

export function start(io) {
    if (state.running) return;
    state.ioRef = io;
    state.running = true;
    state.tickHandle = setInterval(async () => {
        try {
            const now = Date.now();
            const tenantIds = await activeTenantIds();
            for (const tid of tenantIds) {
                const payload = await tenantForecast(tid, now);
                state.latest.set(tid, payload);
                if (state.ioRef) state.ioRef.to(`tenant:${tid}`).emit('forecast:tick', payload);
            }
        } catch (e) {
            logger.warn({ err: e.message }, 'forecast tick failed');
        }
    }, TICK_MS);
    logger.info({ tickMs: TICK_MS, horizonS: HORIZON_S }, 'Pre-Crime forecaster online');
}

export function stop() {
    if (state.tickHandle) clearInterval(state.tickHandle);
    state.tickHandle = null;
    state.running = false;
}

export function snapshot(tenantId) {
    return state.latest.get(tenantId) || { assets: [], cells: [], hotZones: [], horizon_s: HORIZON_S, ts: Date.now() };
}

async function activeTenantIds() {
    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`SELECT set_config('app.role','superadmin',true)`);
        const r = await client.query(`SELECT DISTINCT tenant_id FROM assets WHERE asset_type='aircraft' AND icao24 IS NOT NULL`);
        await client.query('COMMIT');
        return r.rows.map(r => r.tenant_id);
    } finally { client.release(); }
}
