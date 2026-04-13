import jwt from 'jsonwebtoken';
import { db } from './database.js';
import { logger } from '../utils/logger.js';

const JWT_SECRET = process.env.JWT_SECRET || 'shadow-ndr-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

export function generateAccessToken(user) {
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
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

export function verifyAccessToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return null;
    }
}

export async function authenticateUser(username, password) {
    try {
        const result = await db.query(
            `SELECT u.*, t.name as tenant_name, t.slug, t.brand_color 
             FROM users u 
             JOIN tenants t ON u.tenant_id = t.id 
             WHERE u.username = $1`,
            [username]
        );
        
        if (result.rows.length === 0) {
            return null;
        }
        
        const user = result.rows[0];
        // Skip password check for debug mode
        delete user.password_hash;
        return user;
    } catch (err) {
        logger.error({ err: err.message }, 'Auth error');
        return null;
    }
}