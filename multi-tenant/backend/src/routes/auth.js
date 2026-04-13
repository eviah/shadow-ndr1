import jwt from 'jsonwebtoken';
import { Router } from 'express';
import { createHash, randomBytes } from 'crypto';
import { db } from '../services/database.js';
import { authenticate } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import { z } from 'zod';

const router = Router();

// Validation schemas
const LoginSchema = z.object({
    username: z.string().min(3).max(100),
    password: z.string().min(1)
});

const RefreshSchema = z.object({
    refreshToken: z.string().min(10)
});

// Helper to generate access token
function generateAccessToken(user) {
    return jwt.sign(
        {
            id: user.id,
            username: user.username,
            tenant_id: user.tenant_id,
            tenant_name: user.tenant_name,
            slug: user.slug,
            role: user.role,
            brand_color: user.brand_color
        },
        process.env.JWT_SECRET || 'shadow-ndr-secret-key',
        { expiresIn: process.env.JWT_ACCESS_EXPIRES || '24h' }
    );
}

// Helper to generate refresh token (store in DB)
async function generateRefreshToken(userId, tenantId, ip, userAgent) {
    const raw = randomBytes(48).toString('hex');
    const hash = createHash('sha256').update(raw).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await db.query(
        `INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [userId, tenantId, hash, expiresAt, ip, userAgent]
    );
    return raw;
}

// ─── LOGIN endpoint ─────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
    try {
        const { username, password } = LoginSchema.parse(req.body);
        
        const result = await db.query(
            `SELECT u.*, t.name as tenant_name, t.slug, t.brand_color 
             FROM users u 
             JOIN tenants t ON u.tenant_id = t.id 
             WHERE u.username = $1`,
            [username]
        );
        
        if (result.rows.length === 0) {
            logger.warn({ username, ip: req.ip }, 'Login failed – user not found');
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        
        const user = result.rows[0];
        
        // Debug mode - skip password check
        // In production: add bcrypt compare here
        
        // Generate tokens
        const accessToken = generateAccessToken(user);
        const refreshToken = await generateRefreshToken(user.id, user.tenant_id, req.ip, req.headers['user-agent']);
        
        // Log successful login
        await db.query(
            `UPDATE users SET last_login = NOW(), login_count = login_count + 1 WHERE id = $1`,
            [user.id]
        );
        
        // Set refresh token as HTTP‑only cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        
        res.json({
            success: true,
            accessToken,
            user: {
                id: user.id,
                username: user.username,
                tenant_id: user.tenant_id,
                tenant_name: user.tenant_name,
                slug: user.slug,
                role: user.role,
                brand_color: user.brand_color
            }
        });
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ success: false, error: err.errors });
        }
        logger.error({ err: err.message }, 'Login error');
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// ─── REFRESH token endpoint ─────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
    try {
        const { refreshToken } = RefreshSchema.parse(req.body);
        const hash = createHash('sha256').update(refreshToken).digest('hex');
        
        const result = await db.query(
            `SELECT rt.*, u.*, t.name as tenant_name, t.slug
             FROM refresh_tokens rt
             JOIN users u ON rt.user_id = u.id
             JOIN tenants t ON u.tenant_id = t.id
             WHERE rt.token_hash = $1 AND rt.revoked = FALSE AND rt.expires_at > NOW()`,
            [hash]
        );
        
        if (!result.rows.length) {
            return res.status(401).json({ success: false, error: 'Invalid or expired refresh token' });
        }
        
        const user = result.rows[0];
        
        // Revoke old token
        await db.query(`UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`, [hash]);
        
        // Generate new tokens
        const accessToken = generateAccessToken(user);
        const newRefreshToken = await generateRefreshToken(user.id, user.tenant_id, req.ip, req.headers['user-agent']);
        
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        
        res.json({ success: true, accessToken });
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ success: false, error: err.errors });
        }
        logger.error({ err: err.message }, 'Refresh error');
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// ─── LOGOUT endpoint (simplified, no Redis) ─────────────────────────────────
router.post('/logout', authenticate, async (req, res) => {
    try {
        // Revoke refresh token if provided
        const refreshToken = req.body.refreshToken || req.cookies?.refreshToken;
        if (refreshToken) {
            const hash = createHash('sha256').update(refreshToken).digest('hex');
            await db.query(`UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`, [hash]);
        }
        
        res.clearCookie('refreshToken');
        res.json({ success: true, message: 'Logged out' });
    } catch (err) {
        logger.error({ err: err.message }, 'Logout error');
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// ─── GET current user info ──────────────────────────────────────────────────
router.get('/me', authenticate, async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT u.id, u.username, u.email, u.role, u.last_login, u.login_count,
                    t.name AS tenant_name, t.slug, t.brand_color
             FROM users u 
             JOIN tenants t ON u.tenant_id = t.id 
             WHERE u.id = $1`,
            [req.user.id]
        );
        
        if (!rows.length) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        logger.error({ err: err.message }, 'Get me error');
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

export default router;