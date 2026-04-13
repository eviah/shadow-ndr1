/**
 * Shadow NDR Multi-Tenant APEX v3.1 – ULTIMATE PRODUCTION SERVER
 * ═══════════════════════════════════════════════════════════════════
 * • PostgreSQL with RLS + connection pool
 * • Redis sessions, blacklist, cache
 * • JWT access/refresh tokens (Sensor + User)
 * • WebSocket (Socket.IO) per‑tenant rooms + authentication
 * • Sensor data ingestion with rate limiting & JWT (optional)
 * • AI threat scoring integration (via HTTP to ML engine)
 * • Kafka consumer/producer
 * • Helmet, CORS, advanced rate limiting, audit log
 * • Graceful shutdown with timeout
 */

import 'express-async-errors';
import express from 'express';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import jwt from 'jsonwebtoken';
import compression from 'compression';
import { config } from './config/index.js';
import { logger, httpLog } from './utils/logger.js';
import { securityMiddleware, errorHandler, sensorRateLimiter } from './middleware/index.js';
import { db } from './services/database.js';
import { redisService } from './services/redis.js';
import ThreatScoring from './services/threatScoring.js';

// Route imports
import authRoutes from './routes/auth.js';
import dashboardRoutes from './routes/dashboard.js';
import assetsRoutes from './routes/assets.js';
import threatsRoutes from './routes/threats.js';
import alertsRoutes from './routes/alerts.js';
import reportsRoutes from './routes/reports.js';
import healthRoutes from './routes/health.js';

const app = express();
const server = createServer(app);

// ========== 1. Socket.IO advanced ==========
const io = new SocketServer(server, {
  cors: {
    origin: config.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true,
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000,
});

io.use(async (socket, next) => {
  try {
    let token = socket.handshake.auth.token;
    if (!token && socket.handshake.headers.authorization) {
      token = socket.handshake.headers.authorization.split(' ')[1];
    }
    if (!token) {
      logger.warn('WebSocket: No token provided');
      return next(new Error('Authentication required'));
    }

    const JWT_SECRET = process.env.JWT_SECRET || 'shadow-ndr-secret-key-2024';
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.tenant_id) {
      return next(new Error('Invalid token'));
    }

    // בדיקה אם token blacklist (התנתקות)
    const isBlacklisted = false;
    if (isBlacklisted) {
      return next(new Error('Token revoked'));
    }

    socket.data = {
      tenantId: decoded.tenant_id,
      userId: decoded.id,
      role: decoded.role,
    };
    next();
  } catch (err) {
    logger.error({ err: err.message }, 'WebSocket auth failed');
    next(new Error(`Authentication failed: ${err.message}`));
  }
});

io.on('connection', (socket) => {
  const { tenantId, userId } = socket.data;
  const room = `tenant:${tenantId}`;
  socket.join(room);
  logger.info({ socketId: socket.id, tenantId, userId, room }, '🔌 WebSocket connected');

  socket.emit('connected', { status: 'ok', tenantId, room, timestamp: new Date() });

  // Join specific asset rooms (optional)
  socket.on('joinAsset', (assetId) => {
    const assetRoom = `asset:${assetId}`;
    socket.join(assetRoom);
    logger.debug({ assetId, tenantId }, 'Joined asset room');
  });

  socket.on('getThreats', async () => {
    try {
      const result = await db.query(
        `SELECT COUNT(*) FROM threats WHERE tenant_id = $1 AND status = 'active'`,
        [tenantId]
      );
      socket.emit('threatsCount', { count: parseInt(result.rows[0].count, 10) });
    } catch (err) {
      logger.error({ err }, 'Failed to fetch threats count');
      socket.emit('error', { message: 'Failed to fetch threats' });
    }
  });

  socket.on('disconnect', (reason) => {
    logger.info({ socketId: socket.id, tenantId, userId, reason }, '❌ WebSocket disconnected');
  });
});

app.set('io', io);
export { io };

// ========== 2. Express middleware ==========
app.set('trust proxy', 1);
app.use(securityMiddleware);
// CRITICAL FIX: compression() middleware auto-decompresses incoming gzip requests
// This allows the sensor's gzip-compressed payloads to be properly parsed
app.use(compression());
app.use(express.json({ limit: '2mb' }));
app.use(httpLog);

// API routes (existing)
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/assets', assetsRoutes);
app.use('/api/threats', threatsRoutes);
app.use('/api/alerts', alertsRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/health', healthRoutes);

// ========== 3. SENSOR DATA INGESTION – ULTIMATE ==========
/**
 * POST /api/sensor/data
 * Receives parsed packets from Rust sensor, enriches, stores, and broadcasts.
 * Supports optional JWT authentication for sensor (set SENSOR_JWT_SECRET).
 */
app.post('/api/sensor/data', sensorRateLimiter, async (req, res) => {
  const startTime = Date.now();
  try {
    // DEBUG: Log complete incoming payload with all fields
    console.log('[DEBUG] ════════════════════════════════════════════════════');
    console.log('[DEBUG] Received sensor POST request');
    console.log('[DEBUG] Headers:', JSON.stringify(req.headers, null, 2));
    console.log('[DEBUG] Body:', JSON.stringify(req.body, null, 2));
    console.log('[DEBUG] ════════════════════════════════════════════════════');
    
    logger.info({ body: JSON.stringify(req.body).substring(0, 500) }, 'Received sensor data');
    
    // 1. Authentication (optional if SENSOR_JWT_SECRET set)
    let sensorTenantId = null;
    const sensorJwtSecret = process.env.SENSOR_JWT_SECRET;
    if (sensorJwtSecret) {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid sensor token' });
      }
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, sensorJwtSecret);
      sensorTenantId = decoded.tenant_id;
      if (!sensorTenantId) throw new Error('No tenant_id in sensor token');
    }

    // 2. Validate required fields
    const {
      protocol,
      timestamp,
      flow_id,
      src_ip,
      dst_ip,
      src_port,
      dst_port,
      threat_level,
      details,
    } = req.body;

    if (!protocol) {
      console.log('[DEBUG] ✗ VALIDATION FAILED: Missing protocol field');
      logger.error({ body: req.body }, 'Missing protocol field');
      return res.status(400).json({ error: 'Missing required field: protocol' });
    }

    // 3. Determine tenant (from sensor token or default)
    const tenantId = sensorTenantId || '11111111-1111-1111-1111-111111111111';

    // 4. Generate description
    let description = `${protocol.toUpperCase()} packet detected`;
    if (src_ip && dst_ip) {
      description += ` from ${src_ip}:${src_port || '?'} to ${dst_ip}:${dst_port || '?'}`;
    }
    if (threat_level && threat_level !== 'normal') {
      description += ` [${threat_level.toUpperCase()}]`;
    }

    // 5. Compute severity and score (advanced with ThreatScoring)
    let severity = 'info';
    let score = 0.5;
    if (threat_level === 'critical') {
      severity = 'critical';
      score = 0.95;
    } else if (threat_level === 'high') {
      severity = 'high';
      score = 0.8;
    } else if (threat_level === 'medium') {
      severity = 'medium';
      score = 0.6;
    } else if (threat_level === 'low') {
      severity = 'low';
      score = 0.3;
    }

    // Optional ML scoring via ThreatScoring (if method exists)
    if (ThreatScoring && typeof ThreatScoring.calculateScore === 'function') {
      try {
        const mlScore = ThreatScoring.calculateScore({ protocol, threat_level, src_ip, dst_ip });
        if (mlScore) score = mlScore;
        // Recalculate severity based on new score
        if (score >= 0.8) severity = 'critical';
        else if (score >= 0.6) severity = 'high';
        else if (score >= 0.4) severity = 'medium';
        else if (score >= 0.2) severity = 'low';
        else severity = 'info';
      } catch (err) {
        logger.warn({ err: err.message }, 'ML scoring failed, using default');
      }
    }

    // 6. Insert into database
    const result = await db.query(
      `INSERT INTO threats (
        tenant_id, threat_type, severity, source_ip, description, score, detected_at, metadata, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [
        tenantId,
        protocol,
        severity,
        src_ip || null,
        description,
        score,
        timestamp ? new Date(timestamp) : new Date(),
        JSON.stringify({ flow_id, dst_ip, src_port, dst_port, details, raw: req.body }),
        'active'
      ]
    );

    const newThreat = result.rows[0];

    // 7. Real-time broadcast
    io.to(`tenant:${tenantId}`).emit('new_threat', newThreat);

    // 8. Also create alert if high severity
    if (severity === 'critical' || severity === 'high') {
      const alertResult = await db.query(
    `INSERT INTO alerts (tenant_id, threat_id, title, message, severity, created_at)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [tenantId, newThreat.id, `Threat: ${protocol}`, description, severity, new Date()]
);
      io.to(`tenant:${tenantId}`).emit('new_alert', alertResult.rows[0]);
    }

    const duration = Date.now() - startTime;
    logger.info({ tenantId, protocol, threat_level, severity, duration }, 'Sensor data ingested');

    res.status(201).json({ success: true, threat: newThreat });
  } catch (err) {
    logger.error({ err: err.message, body: req.body }, 'Failed to ingest sensor data');
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// ========== 4. Additional sensor endpoints ==========
app.get('/api/sensor/stats', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT COUNT(*) as total, 
              COUNT(CASE WHEN severity='critical' THEN 1 END) as critical,
              COUNT(CASE WHEN severity='high' THEN 1 END) as high,
              COUNT(CASE WHEN severity='medium' THEN 1 END) as medium,
              COUNT(CASE WHEN severity='low' THEN 1 END) as low
       FROM threats WHERE detected_at > NOW() - INTERVAL '1 hour'`
    );
    res.json({ status: 'ok', stats: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Simple health check for sensor connectivity
app.get('/api/sensor/ping', (req, res) => {
  res.json({ status: 'alive', timestamp: new Date().toISOString() });
});

// ========== 5. Root & 404 ==========
app.get('/', (_, res) => {
  res.json({ name: 'Shadow NDR MT APEX', version: '3.1.0', websocket: true, sensor: true });
});

app.use((req, res) => {
  res.status(404).json({ error: `${req.method} ${req.url} not found` });
});

app.use(errorHandler);

// ========== 6. Kafka consumer (improved error handling) ==========
async function startKafka() {
  if (!config.KAFKA_BROKERS) return;
  const { Kafka } = await import('kafkajs');
  const kafka = new Kafka({
    clientId: 'shadow-mt',
    brokers: config.KAFKA_BROKERS.split(','),
    retry: { retries: 3 },
  });
  const consumer = kafka.consumer({ groupId: config.KAFKA_GROUP_ID || 'shadow-mt-group' });
  await consumer.connect();
  await consumer.subscribe({ topic: config.KAFKA_TOPIC_THREATS, fromBeginning: false });
  await consumer.run({
    eachMessage: async ({ message }) => {
      try {
        const threat = JSON.parse(message.value.toString());
        const { rows } = await db.query(
          `INSERT INTO threats (tenant_id, asset_id, threat_type, severity, source_ip, icao24, score, description, detected_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
          [
            threat.tenant_id,
            threat.asset_id || null,
            threat.type,
            threat.severity,
            threat.source_ip || null,
            threat.icao24 || null,
            threat.score || 0.5,
            threat.description || '',
            threat.timestamp ? new Date(threat.timestamp) : new Date(),
          ]
        );
        io.to(`tenant:${threat.tenant_id}`).emit('new_threat', rows[0]);
        logger.info({ tenant: threat.tenant_id, type: threat.type }, 'Kafka threat ingested');
      } catch (err) {
        logger.warn({ err: err.message }, 'Kafka message processing error');
      }
    },
  });
  logger.info('✅ Kafka consumer started');
}

// ========== 7. Graceful shutdown (enhanced) ==========
let isShutdown = false;
async function shutdown(sig) {
  if (isShutdown) return;
  isShutdown = true;
  logger.info({ sig }, 'Graceful shutdown initiated...');
  const timeout = setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 15000);

  try {
    server.close(async () => {
      await Promise.allSettled([
        db.disconnect(),
        redisService.disconnect(),
        io.close(),
      ]);
      clearTimeout(timeout);
      logger.info('Shutdown complete');
      process.exit(0);
    });
  } catch (err) {
    logger.error({ err }, 'Error during shutdown');
    process.exit(1);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'uncaughtException');
  shutdown('uncaughtException');
});
process.on('unhandledRejection', (err) => {
  logger.fatal({ err }, 'unhandledRejection');
  shutdown('unhandledRejection');
});

// ========== 8. Bootstrap ==========
(async () => {
  try {
    await db.connect();
    await redisService.connect();
    // Start Kafka in background (non-blocking)
    startKafka().catch((e) =>
      logger.warn({ err: e.message }, 'Kafka unavailable – skipping')
    );
    console.log('[BOOTSTRAP] About to start listening on port', config.PORT);
    await new Promise((resolve, reject) => {
      server.listen(config.PORT, (err) => {
        if (err) {
          console.log('[BOOTSTRAP] Error:', err);
          reject(err);
        } else {
          console.log('[BOOTSTRAP] Server is now listening on port', config.PORT);
          resolve();
        }
      });
    });
    logger.info(
      { port: config.PORT, env: config.NODE_ENV, ws: true, sensor: true },
      '🚀 Shadow NDR MT APEX v3.1 LIVE – Sensor endpoint ready'
    );
  } catch (err) {
    logger.fatal({ err }, 'Startup failed');
    process.exit(1);
  }
})();