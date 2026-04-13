import { Router } from 'express';
import { db } from '../services/database.js';
import { redisService } from '../services/redis.js';

const router = Router();

router.get('/', async (req, res) => {
    const dbStatus = await db.healthCheck();
    const redisStatus = redisService?.isConnected ? redisService.isConnected() : false;
    
    const healthy = dbStatus.healthy;
    
    res.status(healthy ? 200 : 503).json({
        status: healthy ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        services: {
            database: dbStatus,
            redis: { healthy: redisStatus }
        }
    });
});

export default router;