// src/services/redis.js
// =============================================================================
// SHADOW NDR – UPGRADED REDIS SERVICE
// World‑class caching with automatic fallback to in‑memory store
// Features:
//   • Automatic Redis connection with retry strategy
//   • Graceful fallback to in‑memory cache when Redis is unavailable
//   • Full async/await API
//   • TTL support, pattern invalidation, cached() helper
//   • Structured logging with Pino
//   • Zero downtime on Redis failure
// =============================================================================

import Redis from 'ioredis';
import { logger } from '../utils/logger.js';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const CACHE_TTL_DEFAULT = 60; // seconds

class RedisService {
    constructor() {
        this._client = null;
        this._fallback = new Map(); // in‑memory fallback
        this._connected = false;
    }

    async connect() {
        try {
            this._client = new Redis(REDIS_URL, {
                maxRetriesPerRequest: 3,
                enableOfflineQueue: false,
                lazyConnect: true,
                retryStrategy: (times) => {
                    if (times > 5) {
                        logger.warn('Redis connection failed after 5 retries – switching to in‑memory fallback');
                        return null;
                    }
                    return Math.min(times * 100, 3000);
                }
            });

            this._client.on('error', (err) => {
                logger.warn({ err: err.message }, 'Redis error – using in‑memory fallback');
                this._connected = false;
            });

            await this._client.connect();
            this._connected = true;
            logger.info('✅ Redis connected (external)');
        } catch (err) {
            logger.warn({ err: err.message }, 'Redis unavailable – using in‑memory cache');
            this._connected = false;
            this._client = null;
        }
    }

    async disconnect() {
        if (this._client) {
            await this._client.quit();
            this._client = null;
        }
        this._fallback.clear();
        this._connected = false;
        logger.info('Redis service disconnected');
    }

    // -------------------------------------------------------------------------
    // Core operations – automatically use Redis if available, else fallback
    // -------------------------------------------------------------------------
    async get(key) {
        if (this._connected && this._client) {
            try {
                return await this._client.get(key);
            } catch (err) {
                logger.warn({ err: err.message, key }, 'Redis get failed – using fallback');
            }
        }
        // Fallback: in‑memory
        const item = this._fallback.get(key);
        if (item && item.expiry > Date.now()) {
            return item.value;
        }
        this._fallback.delete(key);
        return null;
    }

    async set(key, value, ttlSeconds = CACHE_TTL_DEFAULT) {
        if (this._connected && this._client) {
            try {
                if (ttlSeconds > 0) {
                    await this._client.set(key, value, 'EX', ttlSeconds);
                } else {
                    await this._client.set(key, value);
                }
                return;
            } catch (err) {
                logger.warn({ err: err.message, key }, 'Redis set failed – using fallback');
            }
        }
        // Fallback
        this._fallback.set(key, {
            value: value,
            expiry: Date.now() + (ttlSeconds * 1000)
        });
    }
    // הוסף אחרי הקוד הקיים:

async isTokenBlacklisted(token) {
    try {
        const result = await this.client.get(`blacklist:${token}`);
        return result !== null;
    } catch (err) {
        logger.error({ err }, 'Failed to check token blacklist');
        return false;
    }
}

async blacklistToken(token, expiresInSeconds = 86400) {
    try {
        await this.client.setex(`blacklist:${token}`, expiresInSeconds, 'true');
    } catch (err) {
        logger.error({ err }, 'Failed to blacklist token');
    }
}

    async del(key) {
        if (this._connected && this._client) {
            try {
                await this._client.del(key);
            } catch (err) {
                logger.warn({ err: err.message, key }, 'Redis del failed – using fallback');
            }
        }
        this._fallback.delete(key);
    }

    async invalidate(pattern) {
        // Pattern can be e.g. "dash:*" or "threat:*"
        if (this._connected && this._client) {
            try {
                const keys = await this._client.keys(pattern);
                if (keys.length) {
                    await this._client.del(...keys);
                }
            } catch (err) {
                logger.warn({ err: err.message, pattern }, 'Redis keys/del failed – using fallback');
            }
        }
        // Fallback: iterate over in‑memory keys
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        for (const key of this._fallback.keys()) {
            if (regex.test(key)) {
                this._fallback.delete(key);
            }
        }
    }

    // -------------------------------------------------------------------------
    // High‑level helper: get cached or compute and store
    // -------------------------------------------------------------------------
    async cached(key, ttlSeconds, fn) {
        const cachedValue = await this.get(key);
        if (cachedValue !== null) {
            try {
                return JSON.parse(cachedValue);
            } catch {
                return cachedValue;
            }
        }
        const fresh = await fn();
        await this.set(key, JSON.stringify(fresh), ttlSeconds);
        return fresh;
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------
    isConnected() {
        return this._connected;
    }
}

// Singleton instance
const redisService = new RedisService();

// Convenience exports
export const invalidate = (pattern) => redisService.invalidate(pattern);
export const cached = (key, ttl, fn) => redisService.cached(key, ttl, fn);
export const redis = {
    get: (k) => redisService.get(k),
    set: (k, v, t) => redisService.set(k, v, t),
    del: (k) => redisService.del(k),
    invalidate: (p) => redisService.invalidate(p),
    cached: (k, t, fn) => redisService.cached(k, t, fn)
};

export { redisService };