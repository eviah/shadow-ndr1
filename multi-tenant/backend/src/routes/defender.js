/**
 * Auto-defender status endpoint. Surfaces blocklists, quarantine list, and
 * the recent action log so the UI can render a live "Defense Console" panel.
 *
 *   GET /api/defender/status
 */
import express from 'express';
import { authenticate } from '../middleware/auth.js';
import { getStatus } from '../services/autoDefender.js';

const router = express.Router();
router.use(authenticate);

router.get('/status', (req, res) => {
    res.json({ success: true, data: getStatus(req.user.tenant_id) });
});

export default router;
