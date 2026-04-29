/**
 * Aviation simulator.
 *
 * Flies each seeded aircraft asset between real airports, updating
 * lat/lon/altitude/heading/speed on every tick and broadcasting
 * `asset:position` over Socket.IO so the map can track them in real time.
 *
 * The simulator is intentionally self-contained so the frontend can be
 * demoed without any external ADS-B feed, and so attacks triggered via
 * /api/simulator/attack flow through the same threat lifecycle as real
 * sensor traffic.
 */
import { db } from './database.js';
import { logger } from '../utils/logger.js';
import { upsertActiveThreat } from './threatLifecycle.js';

// ── Airports (lat, lon, altitude ft) ──────────────────────────────────────────
export const AIRPORTS = {
    TLV: { name: 'Ben Gurion (TLV)',  lat: 32.0114, lon: 34.8867, elev: 135  },
    HFA: { name: 'Haifa (HFA)',       lat: 32.8094, lon: 35.0431, elev: 28   },
    ETM: { name: 'Ramon (ETM)',       lat: 29.7236, lon: 35.0114, elev: 288  },
    VDA: { name: 'Ovda (VDA)',        lat: 29.9403, lon: 34.9358, elev: 1492 },
    LCA: { name: 'Larnaca (LCA)',     lat: 34.8751, lon: 33.6249, elev: 8    },
    ATH: { name: 'Athens (ATH)',      lat: 37.9364, lon: 23.9445, elev: 308  },
    IST: { name: 'Istanbul (IST)',    lat: 41.2753, lon: 28.7519, elev: 325  },
    FCO: { name: 'Rome FCO',          lat: 41.8003, lon: 12.2389, elev: 13   },
    CDG: { name: 'Paris CDG',         lat: 49.0097, lon:  2.5479, elev: 392  },
    LHR: { name: 'London LHR',        lat: 51.4700, lon: -0.4543, elev: 83   },
    FRA: { name: 'Frankfurt FRA',     lat: 50.0379, lon:  8.5622, elev: 364  },
    JFK: { name: 'New York JFK',      lat: 40.6413, lon: -73.7781, elev: 13  },
    BKK: { name: 'Bangkok BKK',       lat: 13.6900, lon: 100.7501, elev: 5   },
    DXB: { name: 'Dubai DXB',         lat: 25.2532, lon: 55.3657, elev: 62   },
};

// Default route map keyed by airline ICAO prefix. Each plane picks one at
// random on first tick if not already assigned.
const ROUTE_TEMPLATES = {
    // EL AL — long-haul + Europe
    '4XE': [['TLV','JFK'],['TLV','LHR'],['TLV','CDG'],['TLV','FRA'],['TLV','BKK']],
    // Israir — regional + Europe short-haul
    '4XA': [['TLV','LCA'],['TLV','ATH'],['TLV','FCO'],['HFA','LCA']],
    // Arkia — domestic + Mediterranean
    '4XB': [['TLV','ETM'],['TLV','VDA'],['TLV','LCA'],['VDA','TLV']],
};

const CRUISE_ALT = { '4XE': 39000, '4XA': 34000, '4XB': 32000 };
const CRUISE_KTS = { '4XE': 490,   '4XA': 440,   '4XB': 420   };
const TICK_MS    = Number(process.env.SIM_TICK_MS || 2000);
// Flight duration scales with great-circle distance: roughly 90s per 1000km
// in simulated time so a demo flight takes ~minutes, not hours.
const SIM_SECONDS_PER_KM = Number(process.env.SIM_SECONDS_PER_KM || 0.09);

// ── Great-circle helpers ──────────────────────────────────────────────────────
const toRad = d => d * Math.PI / 180;
const toDeg = r => r * 180 / Math.PI;

function haversineKm(a, b) {
    const R = 6371, dLat = toRad(b.lat - a.lat), dLon = toRad(b.lon - a.lon);
    const h = Math.sin(dLat/2)**2 +
              Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon/2)**2;
    return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}
function bearing(a, b) {
    const φ1 = toRad(a.lat), φ2 = toRad(b.lat), Δλ = toRad(b.lon - a.lon);
    const y = Math.sin(Δλ) * Math.cos(φ2);
    const x = Math.cos(φ1)*Math.sin(φ2) - Math.sin(φ1)*Math.cos(φ2)*Math.cos(Δλ);
    return (toDeg(Math.atan2(y, x)) + 360) % 360;
}
function interpolate(a, b, t) {
    // Linear great-circle-ish interpolation — visually fine for demo distances.
    return { lat: a.lat + (b.lat - a.lat) * t, lon: a.lon + (b.lon - a.lon) * t };
}

// ── Flight state per plane (in-memory) ────────────────────────────────────────
class Flight {
    constructor(asset) {
        this.assetId   = asset.id;
        this.tenantId  = asset.tenant_id;
        this.icao24    = asset.icao24;
        this.callsign  = asset.callsign || asset.registration || asset.icao24;
        this.prefix    = (asset.icao24 || '').slice(0, 3);
        this.paused    = false;
        this.pickRoute();
    }

    pickRoute(overrideFrom, overrideTo) {
        const tpl = ROUTE_TEMPLATES[this.prefix] || ROUTE_TEMPLATES['4XE'];
        const pick = tpl[Math.floor(Math.random() * tpl.length)];
        this.from = AIRPORTS[overrideFrom || pick[0]];
        this.to   = AIRPORTS[overrideTo   || pick[1]];
        this.fromCode = overrideFrom || pick[0];
        this.toCode   = overrideTo   || pick[1];
        this.distKm   = haversineKm(this.from, this.to);
        this.totalSec = Math.max(60, this.distKm * SIM_SECONDS_PER_KM);
        this.elapsed  = Math.random() * this.totalSec * 0.5;   // stagger
        this.cruise   = CRUISE_ALT[this.prefix] || 35000;
        this.speed    = CRUISE_KTS[this.prefix] || 440;
    }

    tick(dtSec) {
        if (this.paused) return this.snapshot();
        this.elapsed += dtSec;
        if (this.elapsed >= this.totalSec) {
            // Turnaround: swap endpoints and pick a new destination
            const newFrom = this.toCode;
            const tpl = ROUTE_TEMPLATES[this.prefix] || ROUTE_TEMPLATES['4XE'];
            const candidates = tpl.filter(r => r[0] === newFrom || r[1] === newFrom);
            let nextTo;
            if (candidates.length) {
                const pair = candidates[Math.floor(Math.random() * candidates.length)];
                nextTo = pair[0] === newFrom ? pair[1] : pair[0];
            } else {
                nextTo = tpl[0][0] === newFrom ? tpl[0][1] : tpl[0][0];
            }
            this.pickRoute(newFrom, nextTo);
            this.elapsed = 0;
        }
        return this.snapshot();
    }

    snapshot() {
        const t = Math.max(0, Math.min(1, this.elapsed / this.totalSec));
        const pos = interpolate(this.from, this.to, t);
        // Climb 0..0.1, cruise 0.1..0.9, descend 0.9..1
        let alt;
        if (t < 0.1)       alt = this.cruise * (t / 0.1);
        else if (t > 0.9)  alt = this.cruise * (1 - (t - 0.9) / 0.1);
        else               alt = this.cruise;
        const hdg = bearing(this.from, this.to);
        return {
            asset_id: this.assetId, tenant_id: this.tenantId, icao24: this.icao24,
            callsign: this.callsign, from: this.fromCode, to: this.toCode,
            lat: pos.lat, lon: pos.lon, altitude_ft: Math.round(alt),
            heading: Math.round(hdg), speed_kts: Math.round(this.speed),
            progress: t,
        };
    }
}

// ── Runtime registry ──────────────────────────────────────────────────────────
const flights = new Map();   // asset_id -> Flight
let tickHandle = null;
let ioRef = null;

async function loadAssets() {
    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`SELECT set_config('app.role','superadmin',true)`);
        const r = await client.query(`
            SELECT id, tenant_id, icao24, callsign, registration
            FROM assets
            WHERE asset_type = 'aircraft' AND icao24 IS NOT NULL
        `);
        await client.query('COMMIT');
        return r.rows;
    } finally { client.release(); }
}

async function persistPosition(snap) {
    await db.tenantQuery(snap.tenant_id, `
        UPDATE assets
        SET latitude = $1, longitude = $2, altitude_ft = $3,
            heading = $4, speed_kts = $5, last_contact = NOW()
        WHERE id = $6
    `, [snap.lat, snap.lon, snap.altitude_ft, snap.heading, snap.speed_kts, snap.asset_id]);
}

export async function start(io) {
    ioRef = io;
    const assets = await loadAssets();
    for (const a of assets) flights.set(a.id, new Flight(a));
    logger.info({ flights: flights.size, tickMs: TICK_MS }, 'Simulator started');

    let last = Date.now();
    tickHandle = setInterval(async () => {
        const now = Date.now();
        const dt  = (now - last) / 1000;
        last = now;
        for (const f of flights.values()) {
            const snap = f.tick(dt);
            try { await persistPosition(snap); } catch (e) {
                logger.warn({ err: e.message, asset: f.assetId }, 'sim persist failed');
            }
            io.to(`tenant:${snap.tenant_id}`).emit('asset:position', snap);
        }
    }, TICK_MS);
}

export function stop() {
    if (tickHandle) clearInterval(tickHandle);
    tickHandle = null;
    flights.clear();
}

// ── Control API (called from routes/simulator.js) ─────────────────────────────
export function listFlights(tenantId) {
    const out = [];
    for (const f of flights.values()) {
        if (f.tenantId === tenantId) out.push(f.snapshot());
    }
    return out;
}
export function getFlight(tenantId, assetId) {
    const f = flights.get(assetId);
    return (f && f.tenantId === tenantId) ? f.snapshot() : null;
}
export function setPaused(tenantId, assetId, paused) {
    const f = flights.get(assetId);
    if (!f || f.tenantId !== tenantId) return false;
    f.paused = !!paused;
    return true;
}
export function reroute(tenantId, assetId, fromCode, toCode) {
    const f = flights.get(assetId);
    if (!f || f.tenantId !== tenantId) return false;
    if (!AIRPORTS[fromCode] || !AIRPORTS[toCode]) return false;
    f.pickRoute(fromCode, toCode);
    return true;
}

/**
 * Fire a synthetic attack against a specific asset — flows through the exact
 * same threat-lifecycle upsert that real sensor traffic uses, so dedupe,
 * asset-level escalation, and auto-resolve all apply.
 */
export async function injectAttack(tenantId, assetId, { severity = 'critical', type = 'spoofing' } = {}) {
    const f = flights.get(assetId);
    if (!f || f.tenantId !== tenantId) return null;
    const { threat, created } = await upsertActiveThreat(tenantId, {
        threat_type: type,
        severity,
        source_ip: '198.51.100.' + (1 + Math.floor(Math.random() * 254)),
        dest_ip: null,
        icao24: f.icao24,
        asset_id: assetId,
        score: severity === 'critical' ? 0.98 : 0.75,
        description: `Simulated ${severity} ${type} attack on ${f.callsign} (${f.icao24})`,
        raw_features: { simulated: true },
        mitre_technique: null,
    }, ioRef);
    if (ioRef) {
        ioRef.to(`tenant:${tenantId}`).emit(created ? 'threat:new' : 'threat:update', threat);
    }
    return threat;
}
