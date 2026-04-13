import { db } from './database.js';
import { logger } from '../utils/logger.js';

/**
 * Log an audit entry
 */
export async function auditLog({ tenantId, userId, username, action, resource, resourceId, details, ip, status = 'success' }) {
    try {
        // Create table if not exists
        await db.query(`
            CREATE TABLE IF NOT EXISTS audit_log (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                tenant_id UUID,
                user_id UUID,
                username VARCHAR(100),
                action VARCHAR(100) NOT NULL,
                resource VARCHAR(100),
                resource_id TEXT,
                details JSONB,
                ip_address INET,
                status VARCHAR(20) DEFAULT 'success',
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        `);
        
        await db.query(
            `INSERT INTO audit_log (tenant_id, user_id, username, action, resource, resource_id, details, ip_address, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
                tenantId || null,
                userId || null,
                username || null,
                action,
                resource || null,
                resourceId || null,
                details ? JSON.stringify(details) : null,
                ip || null,
                status
            ]
        );
    } catch (err) {
        logger.warn({ err: err.message, action }, 'Audit log write failed');
    }
}

// Make sure auditLog is exported as default as well
export default { auditLog };