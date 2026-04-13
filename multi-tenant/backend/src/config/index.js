import { z } from 'zod';
import dotenv from 'dotenv';
dotenv.config();

const schema = z.object({
  NODE_ENV:               z.enum(['development','production','test']).default('development'),
  PORT:                   z.coerce.number().default(3001),
  LOG_LEVEL:              z.string().default('info'),
  DB_HOST:                z.string(),
  DB_PORT:                z.coerce.number().default(5432),
  DB_USER:                z.string(),
  DB_PASSWORD:            z.string(),
  DB_NAME:                z.string(),
  DB_POOL_MIN:            z.coerce.number().default(2),
  DB_POOL_MAX:            z.coerce.number().default(20),
  DB_STATEMENT_TIMEOUT_MS:z.coerce.number().default(10000),
  REDIS_URL:              z.string().default('redis://localhost:6379'),
  JWT_SECRET:             z.string().min(32),
  JWT_EXPIRES_IN:         z.string().default('15m'),
  REFRESH_SECRET:         z.string().min(32),
  REFRESH_EXPIRES_IN:     z.string().default('7d'),
  BCRYPT_ROUNDS:          z.coerce.number().default(10),
  KAFKA_BROKERS:          z.string().optional(),
  KAFKA_TOPIC_THREATS:    z.string().default('shadow.threats'),
  KAFKA_TOPIC_COMMANDS:   z.string().default('shadow.commands'),
  KAFKA_GROUP_ID:         z.string().default('shadow-mt-consumer'),
  CORS_ORIGINS:           z.string().default('http://localhost:3000'),
  RATE_LIMIT_MAX:         z.coerce.number().default(300),
  WS_HEARTBEAT_MS:        z.coerce.number().default(30000),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('❌ Config validation failed:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}
export const config = parsed.data;
