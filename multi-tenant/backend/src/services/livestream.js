/**
 * Live Threat Stream — Redis Pub/Sub → Socket.IO bridge.
 *
 * Any service in the cluster (the Rust sensor, shadow-ml, the Python
 * shadow-api, a CRON job) can `PUBLISH ndr:threats:tenant:<id>` and
 * connected dashboards in that tenant room receive the event in real
 * time. This file is the only place that knows about both Redis and
 * Socket.IO — every other service can stay framework-agnostic.
 *
 * Channels:
 *   ndr:threats:tenant:<tenantId>   → emits 'threat:new'  / 'threat:update'
 *   ndr:alerts:tenant:<tenantId>    → emits 'alert:new'
 *   ndr:assets:tenant:<tenantId>    → emits 'asset:update'
 *   ndr:global:status               → emits 'system:status' to ALL rooms
 *
 * Payload shape (JSON):
 *   { event: 'threat:new', data: <obj>, ts: <iso8601> }
 */

import Redis from 'ioredis';
import { logger } from '../utils/logger.js';

const TENANT_PATTERN = /^ndr:(threats|alerts|assets):tenant:(\d+)$/;

export function startLiveStream(io, opts = {}) {
  const url = opts.redisUrl || process.env.REDIS_URL || 'redis://127.0.0.1:6379';

  // Subscriber connection (must be separate from any cmd connection)
  const sub = new Redis(url, { lazyConnect: true });

  sub.on('error', (err) => {
    logger.error({ err: err.message }, 'livestream: redis subscriber error');
  });

  sub.on('connect', () => {
    logger.info({ url }, '📡 livestream: redis pub/sub connected');
  });

  sub.on('pmessage', (_pattern, channel, raw) => {
    let payload;
    try {
      payload = JSON.parse(raw);
    } catch (err) {
      logger.warn({ channel, err: err.message }, 'livestream: invalid JSON');
      return;
    }

    if (channel === 'ndr:global:status') {
      io.emit('system:status', payload);
      return;
    }

    const m = channel.match(TENANT_PATTERN);
    if (!m) return;
    const [, kind, tenantId] = m;
    const eventName = payload.event || `${kind.slice(0, -1)}:new`;
    io.to(`tenant:${tenantId}`).emit(eventName, payload.data || payload);

    if (process.env.NDR_LIVESTREAM_TRACE === '1') {
      logger.debug({ channel, eventName, tenantId }, 'livestream emit');
    }
  });

  (async () => {
    await sub.connect();
    await sub.psubscribe(
      'ndr:threats:tenant:*',
      'ndr:alerts:tenant:*',
      'ndr:assets:tenant:*',
      'ndr:global:status',
    );
    logger.info('📡 livestream: subscribed to ndr:* patterns');
  })().catch((err) => {
    logger.error({ err: err.message }, 'livestream: subscribe failed');
  });

  // Publisher returned for in-process use (e.g., when the Node backend
  // itself wants to fan-out a freshly-created threat).
  const pub = new Redis(url, { lazyConnect: true });
  pub.connect().catch((err) =>
    logger.warn({ err: err.message }, 'livestream: publisher connect failed'),
  );

  return {
    subscriber: sub,
    publisher: pub,

    async publishThreat(tenantId, event, data) {
      await pub.publish(
        `ndr:threats:tenant:${tenantId}`,
        JSON.stringify({ event, data, ts: new Date().toISOString() }),
      );
    },

    async publishAlert(tenantId, data) {
      await pub.publish(
        `ndr:alerts:tenant:${tenantId}`,
        JSON.stringify({ event: 'alert:new', data, ts: new Date().toISOString() }),
      );
    },

    async publishAssetUpdate(tenantId, data) {
      await pub.publish(
        `ndr:assets:tenant:${tenantId}`,
        JSON.stringify({ event: 'asset:update', data, ts: new Date().toISOString() }),
      );
    },

    async publishGlobalStatus(data) {
      await pub.publish(
        'ndr:global:status',
        JSON.stringify({ event: 'system:status', data, ts: new Date().toISOString() }),
      );
    },

    async stop() {
      await sub.quit().catch(() => {});
      await pub.quit().catch(() => {});
    },
  };
}
