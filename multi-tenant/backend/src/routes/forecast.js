/**
 * Pre-Crime forecast snapshot endpoint.
 *
 *   GET /api/forecast   latest 60s projection + hotspot cells + hot-zone hits
 *
 * The live stream is `forecast:tick` over Socket.IO; this REST endpoint is for
 * cold-start so the UI has data before the first tick arrives.
 */
import express from 'express';
import { authenticate } from '../middleware/auth.js';
import { snapshot } from '../services/preCrimeForecaster.js';

const router = express.Router();
router.use(authenticate);

router.get('/', (req, res) => {
    res.json({ success: true, data: snapshot(req.user.tenant_id) });
});

export default router;
