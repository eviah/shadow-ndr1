import { WebSocketServer, WebSocket } from 'ws';
import { v4 as uuid } from 'uuid';
import { verifyAccessToken } from './auth.js';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

class TenantWSManager {
  constructor() {
    this._wss = null;
    this._clients = new Map();   // id → { ws, tenantId, userId, lastPong }
    this._hbTimer = null;
    this._stats = { connections:0, messages_sent:0 };
  }

  attach(server) {
    this._wss = new WebSocketServer({ server, path: '/ws' });

    this._wss.on('connection', async (ws, req) => {
      // Authenticate via ?token= query param
      const params = new URLSearchParams(req.url.replace('/ws','').replace('?',''));
      const token  = params.get('token');
      if (!token) { ws.close(4001, 'Unauthorized'); return; }

      const decoded = verifyAccessToken(token);
      if (!decoded) { ws.close(4001, 'Invalid token'); return; }

      const id = uuid();
      this._clients.set(id, {
        ws, tenantId: decoded.tenant_id,
        userId: decoded.sub, lastPong: Date.now(),
      });
      this._stats.connections++;

      ws.on('pong',    ()  => { const c = this._clients.get(id); if (c) c.lastPong = Date.now(); });
      ws.on('message', (d) => this._handleMsg(id, d));
      ws.on('close',   ()  => { this._clients.delete(id); });
      ws.on('error',   ()  => { this._clients.delete(id); });

      this._sendTo(id, { event:'connected', data:{ clientId:id, tenant:decoded.tenant_name } });
      logger.debug({ clientId:id, tenant:decoded.tenant_id }, 'WS connected');
    });

    this._hbTimer = setInterval(() => {
      const now = Date.now();
      this._clients.forEach(({ ws, lastPong }, id) => {
        if (now - lastPong > config.WS_HEARTBEAT_MS * 3) {
          ws.terminate(); this._clients.delete(id); return;
        }
        if (ws.readyState === WebSocket.OPEN) ws.ping();
      });
    }, config.WS_HEARTBEAT_MS);

    logger.info('✅ WebSocket server attached (/ws)');
  }

  /** Broadcast to ALL clients of a specific tenant */
  broadcastToTenant(tenantId, payload) {
    const data = JSON.stringify(payload);
    let sent = 0;
    this._clients.forEach(({ ws, tenantId: tid }) => {
      if (tid === tenantId && ws.readyState === WebSocket.OPEN) {
        ws.send(data); sent++; this._stats.messages_sent++;
      }
    });
    return sent;
  }

  /** Broadcast to ALL connected clients (superadmin notifications) */
  broadcastAll(payload) {
    const data = JSON.stringify(payload);
    this._clients.forEach(({ ws }) => {
      if (ws.readyState === WebSocket.OPEN) { ws.send(data); this._stats.messages_sent++; }
    });
  }

  _sendTo(id, payload) {
    const c = this._clients.get(id);
    if (c?.ws.readyState === WebSocket.OPEN) {
      c.ws.send(JSON.stringify(payload)); this._stats.messages_sent++;
    }
  }

  _handleMsg(id, raw) {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'ping') this._sendTo(id, { event:'pong', data:{ ts:Date.now() } });
    } catch {}
  }

  getStats() { return { ...this._stats, activeClients: this._clients.size }; }

  async shutdown() {
    clearInterval(this._hbTimer);
    this._clients.forEach(({ ws }) => ws.terminate());
    this._clients.clear();
    await new Promise(r => this._wss?.close(r));
  }
}

export const wsManager = new TenantWSManager();
