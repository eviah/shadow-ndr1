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
        
        // בדיקת חיבור
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

    async tenantQuery(tenantId, text, params = []) {
        if (!this.pool) {
            throw new Error('Database not connected');
        }
        // פשוט מעביר את השאילתה
        return this.pool.query(text, params);
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