import pg from 'pg';
import { logger } from '../utils/logger.js';

const { Pool } = pg;

class Database {
    constructor() {
        this.pool = null;
    }

    async connect() {
        this.pool = new Pool({
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT) || 5432,
            user: process.env.DB_USER || 'shadow_admin',
            password: process.env.DB_PASSWORD || 'S3cr3t_MT_2025!',
            database: process.env.DB_NAME || 'shadow_ndr_mt',
            max: 20,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 10000,
        });

        const client = await this.pool.connect();
        await client.query('SELECT 1');
        client.release();

        logger.info('✅ PostgreSQL connected');
    }

    async query(text, params = []) {
        if (!this.pool) {
            throw new Error('Database not connected');
        }
        return this.pool.query(text, params);
    }

    /**
     * Run a query with tenant-scoped RLS enforced.
     * Opens a transaction, sets `app.tenant_id` and `app.role` as transaction-local
     * GUCs via set_config(), then runs the query. The policies in rls.sql read those
     * GUCs — outside of this path, tenant tables are inaccessible.
     */
    async tenantQuery(tenantId, text, params = [], role = 'user') {
        if (!this.pool) throw new Error('Database not connected');
        if (tenantId === undefined || tenantId === null || tenantId === '') {
            throw new Error('tenantQuery requires a tenantId');
        }
        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(
                `SELECT set_config('app.tenant_id', $1, true),
                        set_config('app.role',      $2, true)`,
                [String(tenantId), String(role)]
            );
            const result = await client.query(text, params);
            await client.query('COMMIT');
            return result;
        } catch (err) {
            try { await client.query('ROLLBACK'); } catch { /* ignore */ }
            throw err;
        } finally {
            client.release();
        }
    }

    async healthCheck() {
        try {
            await this.pool.query('SELECT 1');
            return { healthy: true };
        } catch (err) {
            return { healthy: false, error: err.message };
        }
    }

    async disconnect() {
        await this.pool?.end();
        logger.info('PostgreSQL disconnected');
    }
}

export const db = new Database();
