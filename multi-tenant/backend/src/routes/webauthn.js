/**
 * WebAuthn endpoints: register / step-up flows.
 * Mounted at /api/webauthn — every endpoint requires a logged-in user.
 */

import express from 'express';
import { authenticate } from '../middleware/auth.js';
import {
  startRegistration,
  finishRegistration,
  startStepUp,
} from '../services/webauthn.js';

const router = express.Router();

router.use(authenticate);

router.post('/register/options', async (req, res) => {
  const opts = await startRegistration(req.user);
  res.json(opts);
});

router.post('/register/verify', async (req, res) => {
  const { response, nickname } = req.body || {};
  if (!response) return res.status(400).json({ error: 'response required' });
  const out = await finishRegistration(req.user, response, nickname);
  res.json(out);
});

router.post('/stepup/options', async (req, res) => {
  const { operation } = req.body || {};
  if (!operation) return res.status(400).json({ error: 'operation required' });
  try {
    const opts = await startStepUp(req.user, operation);
    res.json(opts);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/credentials', async (req, res) => {
  const { db } = await import('../services/database.js');
  const r = await db.query(
    `SELECT id, nickname, device_type, created_at, last_used_at
     FROM webauthn_credentials WHERE user_id = $1
     ORDER BY created_at DESC`,
    [req.user.id],
  );
  res.json({ credentials: r.rows });
});

export default router;
