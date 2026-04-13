import pino from 'pino';
import { config } from '../config/index.js';

export const logger = pino({
  level: config.LOG_LEVEL,
  transport: config.NODE_ENV === 'development'
    ? { target: 'pino-pretty', options: { colorize:true, translateTime:'SYS:HH:MM:ss', ignore:'pid,hostname' } }
    : undefined,
  base: { service: 'shadow-ndr-mt' },
  redact: ['password','password_hash','DB_PASSWORD','authorization'],
});

export const httpLog = (req, res, next) => {
  const t0 = Date.now();
  res.on('finish', () => logger.info({
    method: req.method, url: req.url,
    status: res.statusCode, ms: Date.now()-t0,
    tenant: req.user?.tenant_id,
  }, 'http'));
  next();
};
