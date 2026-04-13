# Shadow NDR Multi-Tenant APEX v2.0

## Upgrades vs v1.0

| Feature | v1 | v2 |
|---------|----|----|
| Password storage | bcrypt | bcrypt (same) |
| Token system | JWT access only | Access (15m) + Refresh (7d) with rotation |
| Token revocation | ✗ | ✅ Redis blacklist |
| Database isolation | tenant_id WHERE clause | ✅ PostgreSQL RLS policies |
| Logging | console.log | ✅ Pino structured (pretty dev / JSON prod) |
| Config validation | none | ✅ Zod (fails fast) |
| Redis caching | ✗ | ✅ Dashboard cached 15s, invalidated on mutation |
| Audit log | ✗ | ✅ All mutations recorded |
| WebSocket auth | ✗ | ✅ JWT on connect, per-tenant rooms |
| Circuit breaker | ✗ | ✅ opossum on dashboard |
| Rate limiting | global | ✅ per IP+tenant |
| Live map | ✗ | ✅ Leaflet radar with aircraft icons |
| Asset detail | ✗ | ✅ Drawer with threat history |
| Report modal | basic | ✅ Full detail + PDF export trigger |
| Toast notifications | ✗ | ✅ WS-driven live toasts |
| Audit log page | ✗ | ✅ Full audit trail UI |
| Font design | Inter | ✅ Syne display + Share Tech Mono + DM Sans |

## Quick Start

```bash
# 1. Start infrastructure
docker-compose up -d

# 2. Backend
cd backend && npm install && npm run dev

# 3. Frontend
cd frontend && npm install && npm run dev

# 4. Open http://localhost:3000
```

## Demo Credentials (password: shadow123)

| Tenant | Username      | Role  |
|--------|---------------|-------|
| EL AL  | elal_admin    | admin |
| EL AL  | elal_analyst  | analyst |
| Israir | israir_admin  | admin |
| Arkia  | arkia_admin   | admin |

## Security Architecture

- **RLS**: PostgreSQL Row-Level Security ensures tenants are isolated at the DB engine level
- **Access tokens**: 15-minute JWT – if stolen, expires quickly
- **Refresh tokens**: 7-day, rotated on use, stored as SHA-256 hash
- **Blacklist**: Redis stores revoked access tokens until expiry
- **Audit log**: Every mutation (threat status, alert ack) written to audit_log table
