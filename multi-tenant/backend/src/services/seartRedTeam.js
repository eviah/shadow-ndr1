/**
 * SEART — Synthetic Evolving Adversarial Red-Team
 *
 * Generative red-team engine that invents novel "alien" radio attacks and
 * evolves them against the live defense surface. Inspired by GAN training:
 * a population of attack signatures (genomes) competes; survivors mutate and
 * crossover into the next generation.
 *
 * The generator produces attacks across 12 dimensions of the radio/cyber
 * spectrum — frequency band, dwell, beam steer, decoy count, payload entropy,
 * jam pattern, propagation, evasion vector, etc. Each attack is fired through
 * the existing simulator/threat-lifecycle so dedupe, asset escalation, and
 * sweeper auto-resolve all apply unchanged.
 *
 * Fitness signal: did the attack reach 'critical' before being auto-resolved
 * (high fitness — slipped through), or was it deduped/contained quickly (low
 * fitness — defenders won). Winners breed; losers extinct. Generation index,
 * lineage parents, and per-gene drift are all persisted and emitted live so
 * the UI can render the evolutionary tree in real time.
 */
import { logger } from '../utils/logger.js';
import { db } from './database.js';
import { injectAttack, listFlights } from './simulator.js';

const POP_SIZE        = Number(process.env.SEART_POP || 8);
const TICK_MS         = Number(process.env.SEART_TICK_MS || 12_000);
const MUTATION_RATE   = Number(process.env.SEART_MUTATION || 0.18);
const CROSSOVER_RATE  = Number(process.env.SEART_CROSSOVER || 0.4);
const ELITES          = 2;
const FREQ_BANDS      = ['VHF-118', 'UHF-225', 'L-1090', 'GPS-L1', 'GPS-L5', 'SATCOM-1.6', 'X-9.4', 'Ku-14'];
const ATTACK_FAMILIES = ['spoofing', 'jamming', 'replay', 'meaconing', 'deauth', 'mitm', 'protocol_fuzz', 'side_channel', 'covert_channel', 'rf_overpower'];
const PROPAGATION     = ['burst', 'sweep', 'sustained', 'pulse_train', 'frequency_hopping', 'phase_coherent'];
const EVASION         = ['none', 'low_duty', 'mimic_legit', 'doppler_shift', 'sub_threshold', 'phantom_carrier'];

const rng = () => Math.random();
const pick = (arr) => arr[Math.floor(rng() * arr.length)];
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

// ── Genome ────────────────────────────────────────────────────────────────────
// A genome is the DNA of one synthetic attack. Mutate/crossover operate over
// these fields. When fired, the genome is rendered into a threat record.
function randomGenome(generation = 0, parents = []) {
    return {
        gen: generation,
        parents,
        family:        pick(ATTACK_FAMILIES),
        freq_band:     pick(FREQ_BANDS),
        propagation:   pick(PROPAGATION),
        evasion:       pick(EVASION),
        dwell_ms:      Math.round(50 + rng() * 950),
        beam_steer:    Math.round(rng() * 360),
        decoys:        Math.floor(rng() * 6),
        entropy:       +(0.3 + rng() * 0.7).toFixed(3),
        power_dbm:     Math.round(-30 + rng() * 70),
        coherence:     +(rng()).toFixed(3),
        polymorphism:  +(rng() * 0.5).toFixed(3),
        severity:      rng() < 0.3 ? 'high' : 'critical',
        // Fitness is filled in after the threat lifecycle responds.
        fitness:       0,
        threatId:      null,
        firedAt:       null,
        resolvedAt:    null,
    };
}

function mutate(g, generation) {
    const next = { ...g, gen: generation, parents: [g.id ?? null], fitness: 0, threatId: null, firedAt: null, resolvedAt: null };
    if (rng() < MUTATION_RATE) next.family       = pick(ATTACK_FAMILIES);
    if (rng() < MUTATION_RATE) next.freq_band    = pick(FREQ_BANDS);
    if (rng() < MUTATION_RATE) next.propagation  = pick(PROPAGATION);
    if (rng() < MUTATION_RATE) next.evasion      = pick(EVASION);
    if (rng() < MUTATION_RATE * 2) next.dwell_ms     = clamp(Math.round(g.dwell_ms + (rng() - 0.5) * 400), 20, 2000);
    if (rng() < MUTATION_RATE * 2) next.beam_steer   = (g.beam_steer + Math.round((rng() - 0.5) * 90) + 360) % 360;
    if (rng() < MUTATION_RATE * 2) next.decoys       = clamp(g.decoys + (rng() < 0.5 ? -1 : 1), 0, 12);
    if (rng() < MUTATION_RATE * 2) next.entropy      = clamp(+(g.entropy + (rng() - 0.5) * 0.2).toFixed(3), 0, 1);
    if (rng() < MUTATION_RATE * 2) next.power_dbm    = clamp(Math.round(g.power_dbm + (rng() - 0.5) * 20), -40, 50);
    if (rng() < MUTATION_RATE * 2) next.coherence    = clamp(+(g.coherence + (rng() - 0.5) * 0.2).toFixed(3), 0, 1);
    if (rng() < MUTATION_RATE)     next.polymorphism = clamp(+(g.polymorphism + (rng() - 0.5) * 0.15).toFixed(3), 0, 1);
    return next;
}

function crossover(a, b, generation) {
    const child = { gen: generation, parents: [a.id, b.id], fitness: 0, threatId: null, firedAt: null, resolvedAt: null };
    const fields = ['family', 'freq_band', 'propagation', 'evasion', 'dwell_ms', 'beam_steer', 'decoys', 'entropy', 'power_dbm', 'coherence', 'polymorphism', 'severity'];
    for (const f of fields) child[f] = rng() < 0.5 ? a[f] : b[f];
    return child;
}

// ── Live state ────────────────────────────────────────────────────────────────
const state = {
    running: false,
    tickHandle: null,
    ioRef: null,
    tenants: new Map(), // tenantId -> { generation, population, history, fittest, totalFired, totalSlipped }
};

let genomeCounter = 1;
const stamp = (g) => { g.id = genomeCounter++; return g; };

// Default: paused. The red team only fires when the operator explicitly hits
// Resume/Fire from the UI. This keeps the alert stream silent during defense
// validation and lets the user see one attack get stopped at a time.
const SEART_DEFAULT_PAUSED = process.env.SEART_AUTOSTART !== '1';

function ensureTenant(tenantId) {
    if (!state.tenants.has(tenantId)) {
        const pop = Array.from({ length: POP_SIZE }, () => stamp(randomGenome(1)));
        state.tenants.set(tenantId, {
            generation: 1,
            population: pop,
            history: [],          // last N generations summary
            fittest: null,
            totalFired: 0,
            totalSlipped: 0,
            paused: SEART_DEFAULT_PAUSED,
        });
    }
    return state.tenants.get(tenantId);
}

// ── Fitness measurement ───────────────────────────────────────────────────────
// A genome scores higher if its threat reached 'critical' and survived for
// longer than peers (defender response time). Resolved-fast → low fitness.
async function measureFitness(tenantId, genome) {
    if (!genome.threatId) return 0;
    try {
        const r = await db.tenantQuery(tenantId, `
            SELECT severity, status, EXTRACT(EPOCH FROM (NOW() - created_at)) AS age_s,
                   EXTRACT(EPOCH FROM (COALESCE(updated_at, NOW()) - created_at)) AS lifetime_s
            FROM threats WHERE id = $1
        `, [genome.threatId]);
        if (!r.rows.length) return 0.1;
        const row = r.rows[0];
        const sevWeight = row.severity === 'critical' ? 1.0 : row.severity === 'high' ? 0.6 : 0.3;
        const lifetime = Math.min(60, Number(row.lifetime_s || 0));
        const lifeBonus = lifetime / 60;
        const slipped = row.status === 'active' && Number(row.age_s) > 8 ? 0.4 : 0;
        return +(sevWeight * 0.5 + lifeBonus * 0.4 + slipped).toFixed(3);
    } catch (e) {
        logger.warn({ err: e.message }, 'SEART fitness probe failed');
        return 0;
    }
}

// ── Fire one genome at a random live flight ───────────────────────────────────
async function fireGenome(tenantId, genome) {
    const flights = listFlights(tenantId);
    if (!flights.length) return null;
    const target = flights[Math.floor(rng() * flights.length)];
    const description = `SEART gen-${genome.gen} ${genome.family} via ${genome.freq_band} ${genome.propagation} (evasion: ${genome.evasion}, decoys: ${genome.decoys}, H=${genome.entropy})`;
    try {
        const threat = await injectAttack(tenantId, target.asset_id, {
            severity: genome.severity,
            type: genome.family,
        });
        if (threat?.id) {
            genome.threatId = threat.id;
            genome.firedAt  = Date.now();
            genome.target   = { asset_id: target.asset_id, callsign: target.callsign, icao24: target.icao24 };
            genome.description = description;
            return threat;
        }
    } catch (e) {
        logger.warn({ err: e.message }, 'SEART fire failed');
    }
    return null;
}

// ── Main evolutionary tick ────────────────────────────────────────────────────
async function evolveTenant(tenantId) {
    const t = ensureTenant(tenantId);
    if (t.paused) return;

    // 1) Score the previous population now that fitness signals have settled
    for (const g of t.population) {
        if (g.threatId && !g.fitness) {
            g.fitness = await measureFitness(tenantId, g);
        }
    }

    const ranked = [...t.population].sort((a, b) => b.fitness - a.fitness);
    const fittest = ranked[0];
    const meanFitness = ranked.reduce((s, g) => s + g.fitness, 0) / Math.max(1, ranked.length);

    // 2) Snapshot history
    t.history.push({
        gen: t.generation,
        meanFitness: +meanFitness.toFixed(3),
        bestFitness: fittest?.fitness ?? 0,
        bestFamily: fittest?.family,
        bestFreq: fittest?.freq_band,
        bestEvasion: fittest?.evasion,
        size: ranked.length,
        ts: Date.now(),
    });
    if (t.history.length > 24) t.history.shift();
    t.fittest = fittest;
    t.totalSlipped += ranked.filter(g => g.fitness > 0.7).length;

    // 3) Breed next generation
    const nextGen = t.generation + 1;
    const elites = ranked.slice(0, ELITES).map(g => stamp(mutate(g, nextGen)));
    const offspring = [];
    while (offspring.length < POP_SIZE - ELITES) {
        const a = ranked[Math.floor(rng() * Math.min(4, ranked.length))];
        const b = ranked[Math.floor(rng() * Math.min(4, ranked.length))];
        const child = rng() < CROSSOVER_RATE && a !== b ? crossover(a, b, nextGen) : mutate(a, nextGen);
        offspring.push(stamp(child));
    }
    t.population  = [...elites, ...offspring];
    t.generation  = nextGen;

    // 4) Fire the new population at random live targets
    for (const g of t.population) {
        const t0 = await fireGenome(tenantId, g);
        if (t0) t.totalFired++;
    }

    // 5) Broadcast generation summary
    if (state.ioRef) {
        state.ioRef.to(`tenant:${tenantId}`).emit('seart:generation', {
            generation: t.generation,
            population: t.population.map(g => ({
                id: g.id, gen: g.gen, parents: g.parents,
                family: g.family, freq_band: g.freq_band, propagation: g.propagation,
                evasion: g.evasion, severity: g.severity, entropy: g.entropy,
                decoys: g.decoys, power_dbm: g.power_dbm, target: g.target,
                threatId: g.threatId, description: g.description,
            })),
            history: t.history,
            totalFired: t.totalFired,
            totalSlipped: t.totalSlipped,
        });
    }
}

// ── Public control surface ────────────────────────────────────────────────────
export function start(io) {
    if (state.running) return;
    state.ioRef = io;
    state.running = true;
    state.tickHandle = setInterval(async () => {
        try {
            // Active tenants are those with at least one aircraft asset
            const tenantIds = await activeTenantIds();
            for (const tid of tenantIds) {
                await evolveTenant(tid);
            }
        } catch (e) {
            logger.warn({ err: e.message }, 'SEART tick failed');
        }
    }, TICK_MS);
    logger.info({ tickMs: TICK_MS, popSize: POP_SIZE }, 'SEART red-team online');
}

export function stop() {
    if (state.tickHandle) clearInterval(state.tickHandle);
    state.tickHandle = null;
    state.running = false;
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

export function setPaused(tenantId, paused) {
    const t = ensureTenant(tenantId);
    t.paused = !!paused;
    return true;
}

export function getStatus(tenantId) {
    const t = ensureTenant(tenantId);
    return {
        running: state.running,
        paused: t.paused,
        generation: t.generation,
        popSize: t.population.length,
        totalFired: t.totalFired,
        totalSlipped: t.totalSlipped,
        history: t.history,
        population: t.population.map(g => ({
            id: g.id, gen: g.gen, parents: g.parents,
            family: g.family, freq_band: g.freq_band, propagation: g.propagation,
            evasion: g.evasion, severity: g.severity, entropy: g.entropy,
            decoys: g.decoys, power_dbm: g.power_dbm, fitness: g.fitness,
            target: g.target, threatId: g.threatId, description: g.description,
        })),
        fittest: t.fittest && {
            id: t.fittest.id, gen: t.fittest.gen, family: t.fittest.family,
            freq_band: t.fittest.freq_band, evasion: t.fittest.evasion,
            fitness: t.fittest.fitness, description: t.fittest.description,
        },
    };
}

export function fireOneNow(tenantId) {
    const t = ensureTenant(tenantId);
    const g = stamp(randomGenome(t.generation));
    t.population.push(g);
    return fireGenome(tenantId, g);
}
