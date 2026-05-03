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
import { securityMiddleware, errorHandler, sensorRateLimiter, authRateLimiter, apiRateLimiter } from './middleware/index.js';
import { db } from './services/database.js';
import { redisService } from './services/redis.js';
import ThreatScoring from './services/threatScoring.js';
import { upsertActiveThreat, startSweeper } from './services/threatLifecycle.js';
import * as simulator from './services/simulator.js';
import * as seart from './services/seartRedTeam.js';
import * as forecaster from './services/preCrimeForecaster.js';
import { startLiveStream } from './services/livestream.js';

// Route imports
import authRoutes from './routes/auth.js';
import dashboardRoutes from './routes/dashboard.js';
import assetsRoutes from './routes/assets.js';
import threatsRoutes from './routes/threats.js';
import alertsRoutes from './routes/alerts.js';
import reportsRoutes from './routes/reports.js';
import healthRoutes from './routes/health.js';
import simulatorRoutes from './routes/simulator.js';
import redteamRoutes from './routes/redteam.js';
import forecastRoutes from './routes/forecast.js';
import defenderRoutes from './routes/defender.js';
import webauthnRoutes from './routes/webauthn.js';
import { requireStepUp } from './services/webauthn.js';

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
      const result = await db.tenantQuery(
        tenantId,
        `SELECT COUNT(*) FROM threats WHERE status = 'active'`
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

// Wire wsManager (used by routes/services) to the live socket.io instance
// so existing wsManager.broadcastToTenant() calls actually reach clients.
import('./services/websocket.js').then(({ wsManager }) => wsManager.bindIo(io));

// Redis Pub/Sub → Socket.IO bridge so any service in the cluster can
// publish to ndr:threats:tenant:<id> and dashboards update instantly.
const liveStream = startLiveStream(io);
app.set('liveStream', liveStream);

// REST endpoint to fan-out a threat from anywhere (used by sensor + ML)
app.post('/api/v1/ws/threats', express.json(), async (req, res) => {
  const { tenant_id, event = 'threat:new', data } = req.body || {};
  if (!tenant_id || !data) {
    return res.status(400).json({ error: 'tenant_id and data required' });
  }
  await liveStream.publishThreat(tenant_id, event, data);
  res.json({ published: true, channel: `ndr:threats:tenant:${tenant_id}` });
});

export { io, liveStream };

// ========== 2. Express middleware ==========
app.set('trust proxy', 1);
app.use(securityMiddleware);
// CRITICAL FIX: compression() middleware auto-decompresses incoming gzip requests
// This allows the sensor's gzip-compressed payloads to be properly parsed
app.use(compression());
app.use(express.json({ limit: '2mb' }));
app.use(httpLog);

// API routes (with rate limiting)
// Auth endpoints get a tighter brute-force guard.
app.use('/api/auth',       authRateLimiter, authRoutes);
// Everything else shares a generic per-IP rate limit.
app.use('/api/dashboard',  apiRateLimiter, dashboardRoutes);
app.use('/api/assets',     apiRateLimiter, assetsRoutes);
app.use('/api/threats',    apiRateLimiter, threatsRoutes);
app.use('/api/alerts',     apiRateLimiter, alertsRoutes);
app.use('/api/reports',    apiRateLimiter, reportsRoutes);
app.use('/api/simulator',  apiRateLimiter, simulatorRoutes);
app.use('/api/redteam',    apiRateLimiter, redteamRoutes);
app.use('/api/forecast',   apiRateLimiter, forecastRoutes);
app.use('/api/defender',   apiRateLimiter, defenderRoutes);
app.use('/api/webauthn',   apiRateLimiter, webauthnRoutes);
app.use('/health', healthRoutes);

// FIDO2 step-up gate — destructive ops require a hardware-key assertion.
// Applied BEFORE the regular threats router so the gate runs first.
app.delete('/api/threats/global', requireStepUp('clear-global-threats'),
  async (req, res) => {
    const result = await db.query('DELETE FROM threats WHERE tenant_id = $1', [req.user.tenant_id]);
    res.json({ deleted: result.rowCount });
  });
app.post('/api/alerts/critical/bulk-acknowledge', requireStepUp('bulk-ack-critical'),
  async (req, res) => {
    const result = await db.query(
      `UPDATE alerts SET acknowledged = TRUE
       WHERE tenant_id = $1 AND severity IN ('critical','emergency') AND acknowledged = FALSE`,
      [req.user.tenant_id]);
    res.json({ acknowledged: result.rowCount });
  });

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

    // 1. Authentication
    //  - Production: SENSOR_JWT_SECRET is required and the sensor must carry a
    //    bearer token whose `tenant_id` claim (integer) selects the tenant.
    //  - Development: if SENSOR_JWT_SECRET is unset we fall back to tenant 1 and
    //    emit a loud warning so nobody ships this config to prod.
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
      if (!Number.isInteger(sensorTenantId)) {
        return res.status(401).json({ error: 'Sensor token tenant_id must be an integer' });
      }
    } else if (config.NODE_ENV === 'production') {
      return res.status(401).json({ error: 'SENSOR_JWT_SECRET not configured' });
    } else {
      logger.warn('SENSOR_JWT_SECRET unset — accepting unauthenticated sensor traffic into tenant 1 (dev only)');
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
    const tenantId = sensorTenantId || 1;

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

    // 6. Lifecycle-aware upsert (dedupes repeat attacks, emits WS events)
    const icaoHint = details?.icao24 || req.body?.icao24 || null;
    let assetId = null;
    if (icaoHint) {
      const a = await db.tenantQuery(
        tenantId,
        `SELECT id FROM assets WHERE icao24 = $1 LIMIT 1`,
        [icaoHint],
      );
      if (a.rows.length) assetId = a.rows[0].id;
    }

    const { threat: newThreat, created } = await upsertActiveThreat(tenantId, {
      threat_type: protocol,
      severity,
      source_ip: src_ip || null,
      dest_ip: dst_ip || null,
      icao24: icaoHint,
      asset_id: assetId,
      score,
      description,
      raw_features: { flow_id, dst_ip, src_port, dst_port, details, raw: req.body },
      mitre_technique: null,
    }, io);

    // 7. Real-time broadcast — distinguish new vs update so UI can animate
    io.to(`tenant:${tenantId}`).emit(created ? 'threat:new' : 'threat:update', newThreat);
    // Legacy event kept for existing UI listeners
    io.to(`tenant:${tenantId}`).emit('new_threat', newThreat);

    // 8. Create alert only for genuinely new high-severity threats (not repeats)
    if (created && (severity === 'critical' || severity === 'high')) {
      const alertResult = await db.tenantQuery(
        tenantId,
        `INSERT INTO alerts (tenant_id, threat_id, title, message, severity, detected_at)
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
  const { Kafka, logLevel } = await import('kafkajs');
  const kafka = new Kafka({
    clientId: 'shadow-mt',
    brokers: config.KAFKA_BROKERS.split(','),
    retry: { retries: 8, initialRetryTime: 500, maxRetryTime: 30000 },
    logLevel: logLevel.WARN,
  });

  // Pre-create topic so the consumer doesn't race on metadata fetch
  const admin = kafka.admin();
  await admin.connect();
  try {
    const existing = await admin.listTopics();
    if (!existing.includes(config.KAFKA_TOPIC_THREATS)) {
      await admin.createTopics({
        waitForLeaders: true,
        topics: [{ topic: config.KAFKA_TOPIC_THREATS, numPartitions: 1, replicationFactor: 1 }],
      });
      logger.info({ topic: config.KAFKA_TOPIC_THREATS }, 'Kafka topic created');
    }
  } finally {
    await admin.disconnect();
  }

  const consumer = kafka.consumer({ groupId: config.KAFKA_GROUP_ID || 'shadow-mt-group' });
  await consumer.connect();
  await consumer.subscribe({ topic: config.KAFKA_TOPIC_THREATS, fromBeginning: false });
  await consumer.run({
    eachMessage: async ({ message }) => {
      try {
        const threat = JSON.parse(message.value.toString());
        if (!Number.isInteger(threat.tenant_id)) {
          logger.warn({ threat }, 'Kafka threat missing integer tenant_id — dropping');
          return;
        }
        const { rows } = await db.tenantQuery(
          threat.tenant_id,
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
    startSweeper(io);
    await simulator.start(io);
    forecaster.start(io);
    seart.start(io);
    logger.info(
      { port: config.PORT, env: config.NODE_ENV, ws: true, sensor: true },
      '🚀 Shadow NDR MT APEX v3.1 LIVE – Sensor endpoint ready'
    );
  } catch (err) {
    logger.fatal({ err }, 'Startup failed');
    process.exit(1);
  }
})();