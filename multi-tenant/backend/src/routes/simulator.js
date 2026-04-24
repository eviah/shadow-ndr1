/**
 * Simulator control endpoints — tenant-scoped via JWT middleware.
 *
 *   GET    /api/simulator/airports              world airports lookup
 *   GET    /api/simulator/flights               every live flight for the tenant
 *   GET    /api/simulator/flights/:assetId      one flight snapshot
 *   POST   /api/simulator/flights/:assetId/pause    body: { paused: boolean }
 *   POST   /api/simulator/flights/:assetId/route    body: { from, to } (airport codes)
 *   POST   /api/simulator/flights/:assetId/attack   body: { severity?, type? }
 */
import express from 'express';
import { authenticate } from '../middleware/auth.js';
import {
    AIRPORTS, listFlights, getFlight,
    setPaused, reroute, injectAttack,
} from '../services/simulator.js';

const router = express.Router();
router.use(authenticate);

router.get('/airports', (_req, res) => {
    res.json({ success: true, data: AIRPORTS });
});

router.get('/flights', (req, res) => {
    res.json({ success: true, data: listFlights(req.user.tenant_id) });
});

router.get('/flights/:assetId', (req, res) => {
    const snap = getFlight(req.user.tenant_id, Number(req.params.assetId));
    if (!snap) return res.status(404).json({ success: false, error: 'not found' });
    res.json({ success: true, data: snap });
});

router.post('/flights/:assetId/pause', (req, res) => {
    const ok = setPaused(req.user.tenant_id, Number(req.params.assetId), !!req.body.paused);
    if (!ok) return res.status(404).json({ success: false, error: 'not found' });
    res.json({ success: true });
});

router.post('/flights/:assetId/route', (req, res) => {
    const { from, to } = req.body || {};
    if (!from || !to) return res.status(400).json({ success: false, error: 'from and to required' });
    const ok = reroute(req.user.tenant_id, Number(req.params.assetId), from, to);
    if (!ok) return res.status(400).json({ success: false, error: 'invalid flight or airport code' });
    res.json({ success: true });
});

router.post('/flights/:assetId/attack', async (req, res) => {
    const { severity, type } = req.body || {};
    const threat = await injectAttack(req.user.tenant_id, Number(req.params.assetId), { severity, type });
    if (!threat) return res.status(404).json({ success: false, error: 'not found' });
    res.json({ success: true, data: threat });
});

export default router;
