/**
 * SEART (Synthetic Evolving Adversarial Red-Team) control endpoints.
 *
 *   GET   /api/redteam/status       current generation, population, history
 *   POST  /api/redteam/pause        body: { paused: boolean }
 *   POST  /api/redteam/fire-now     fire one ad-hoc genome at a random flight
 */
import express from 'express';
import { authenticate, requireRole } from '../middleware/auth.js';
import * as seart from '../services/seartRedTeam.js';

const router = express.Router();
router.use(authenticate);

router.get('/status', (req, res) => {
    res.json({ success: true, data: seart.getStatus(req.user.tenant_id) });
});

router.post('/pause', requireRole('admin', 'superadmin'), (req, res) => {
    seart.setPaused(req.user.tenant_id, !!req.body?.paused);
    res.json({ success: true, data: seart.getStatus(req.user.tenant_id) });
});

router.post('/fire-now', requireRole('admin', 'superadmin'), async (req, res) => {
    const t = await seart.fireOneNow(req.user.tenant_id);
    if (!t) return res.status(409).json({ success: false, error: 'no live flights to target' });
    res.json({ success: true, data: t });
});

export default router;
