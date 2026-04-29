/**
 * FIDO2 / WebAuthn step-up authentication.
 *
 * Used for "destructive" operations — clearing global threat logs,
 * acknowledging critical alerts in bulk, deleting assets, etc. Even
 * if an admin's password is stolen, the attacker still cannot do
 * these actions without the registered hardware key.
 *
 * Two flows:
 *   register     POST /webauthn/register/options  → POST /webauthn/register/verify
 *   step-up      POST /webauthn/stepup/options    → request includes signed
 *                  assertion in the X-WebAuthn-Assertion header on the
 *                  destructive endpoint
 *
 * Library: @simplewebauthn/server  (peer of @simplewebauthn/browser)
 */

import crypto from 'node:crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { db } from './database.js';
import { logger } from '../utils/logger.js';

const RP_NAME    = process.env.WEBAUTHN_RP_NAME    || 'Shadow NDR';
const RP_ID      = process.env.WEBAUTHN_RP_ID      || 'localhost';
const RP_ORIGIN  = process.env.WEBAUTHN_RP_ORIGIN  || 'http://localhost:3000';
const CHALLENGE_TTL_MS = 5 * 60 * 1000;  // 5 minutes

// ─── Challenge storage ─────────────────────────────────────────────────────

async function saveChallenge(challenge, userId, purpose) {
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
  await db.query(
    `INSERT INTO webauthn_challenges (challenge, user_id, purpose, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [challenge, userId, purpose, expiresAt],
  );
}

async function consumeChallenge(challenge, userId, purpose) {
  const r = await db.query(
    `DELETE FROM webauthn_challenges
     WHERE challenge = $1 AND user_id = $2 AND purpose = $3
       AND expires_at > NOW()
     RETURNING challenge`,
    [challenge, userId, purpose],
  );
  return r.rows.length > 0;
}

// ─── Registration ─────────────────────────────────────────────────────────

export async function startRegistration(user) {
  const existing = await db.query(
    `SELECT credential_id FROM webauthn_credentials WHERE user_id = $1`,
    [user.id],
  );
  const opts = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: Buffer.from(String(user.id)),
    userName: user.username || user.email,
    userDisplayName: user.full_name || user.username,
    attestationType: 'none',
    excludeCredentials: existing.rows.map((r) => ({
      id: Buffer.from(r.credential_id, 'base64url'),
      type: 'public-key',
    })),
    authenticatorSelection: {
      userVerification: 'preferred',
      residentKey: 'preferred',
    },
  });
  await saveChallenge(opts.challenge, user.id, 'register');
  return opts;
}

export async function finishRegistration(user, response, nickname) {
  const expectedChallenge = response.expectedChallenge || response.challenge;
  const ok = await consumeChallenge(expectedChallenge, user.id, 'register');
  if (!ok) throw new Error('challenge expired or already used');

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: RP_ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: false,
  });
  if (!verification.verified) throw new Error('registration failed');

  const reg = verification.registrationInfo;
  await db.query(
    `INSERT INTO webauthn_credentials
       (user_id, tenant_id, credential_id, public_key, counter,
        transports, device_type, backed_up, nickname)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      user.id, user.tenant_id,
      Buffer.from(reg.credentialID).toString('base64url'),
      Buffer.from(reg.credentialPublicKey),
      reg.counter,
      response.response?.transports || [],
      reg.credentialDeviceType,
      reg.credentialBackedUp,
      nickname || null,
    ],
  );
  logger.info({ userId: user.id }, 'webauthn: credential registered');
  return { ok: true, credential_id: Buffer.from(reg.credentialID).toString('base64url') };
}

// ─── Step-up (per-operation) ──────────────────────────────────────────────

export async function startStepUp(user, operation) {
  const creds = await db.query(
    `SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = $1`,
    [user.id],
  );
  if (creds.rows.length === 0) {
    throw new Error('no FIDO2 credentials registered for this user');
  }

  const opts = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
    allowCredentials: creds.rows.map((c) => ({
      id: Buffer.from(c.credential_id, 'base64url'),
      type: 'public-key',
      transports: c.transports || [],
    })),
  });

  await saveChallenge(opts.challenge, user.id, `stepup:${operation}`);
  return opts;
}

export async function verifyStepUp(user, operation, assertion) {
  if (!assertion || !assertion.response || !assertion.id) {
    throw new Error('malformed assertion');
  }

  const expectedChallenge = assertion.expectedChallenge ||
    Buffer.from(assertion.response.clientDataJSON, 'base64url').toString();
  // Pull challenge from clientDataJSON safely
  let challengeFromClient = null;
  try {
    const clientData = JSON.parse(
      Buffer.from(assertion.response.clientDataJSON, 'base64url').toString(),
    );
    challengeFromClient = clientData.challenge;
  } catch {
    throw new Error('malformed clientDataJSON');
  }

  const ok = await consumeChallenge(challengeFromClient, user.id, `stepup:${operation}`);
  if (!ok) throw new Error('challenge expired or already used');

  const credRow = await db.query(
    `SELECT credential_id, public_key, counter FROM webauthn_credentials
     WHERE user_id = $1 AND credential_id = $2`,
    [user.id, assertion.id],
  );
  if (credRow.rows.length === 0) throw new Error('unknown credential');

  const stored = credRow.rows[0];
  const verification = await verifyAuthenticationResponse({
    response: assertion,
    expectedChallenge: challengeFromClient,
    expectedOrigin: RP_ORIGIN,
    expectedRPID: RP_ID,
    authenticator: {
      credentialID: Buffer.from(stored.credential_id, 'base64url'),
      credentialPublicKey: stored.public_key,
      counter: Number(stored.counter),
    },
    requireUserVerification: false,
  });
  if (!verification.verified) throw new Error('assertion verification failed');

  await db.query(
    `UPDATE webauthn_credentials
       SET counter = $1, last_used_at = NOW()
       WHERE credential_id = $2`,
    [verification.authenticationInfo.newCounter, stored.credential_id],
  );
  logger.info({ userId: user.id, operation }, 'webauthn: step-up verified');
  return true;
}

// ─── Express middleware ───────────────────────────────────────────────────

/**
 * requireStepUp('delete-threats')  → 401 if no valid assertion in the header.
 * Apply on DESTRUCTIVE routes only. The frontend collects the assertion via
 * @simplewebauthn/browser, then sends the destructive request with header:
 *   X-WebAuthn-Assertion: <base64-json-encoded assertion>
 */
export function requireStepUp(operation) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'authentication required' });
    }
    const header = req.get('x-webauthn-assertion');
    if (!header) {
      return res.status(401).json({
        error: 'webauthn_required',
        operation,
        message: 'this operation requires a FIDO2 step-up assertion',
      });
    }
    let assertion;
    try {
      assertion = JSON.parse(Buffer.from(header, 'base64').toString());
    } catch {
      return res.status(400).json({ error: 'malformed assertion header' });
    }
    try {
      await verifyStepUp(req.user, operation, assertion);
      next();
    } catch (err) {
      logger.warn({ userId: req.user.id, err: err.message }, 'webauthn step-up rejected');
      return res.status(403).json({ error: 'webauthn_failed', detail: err.message });
    }
  };
}
