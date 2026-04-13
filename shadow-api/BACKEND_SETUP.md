# Shadow API – Backend Setup Guide

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- PostgreSQL 14+
- Redis
- ClickHouse

### 1. Install Dependencies

```bash
cd shadow-api
python -m venv venv

# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Setup Database

PostgreSQL must be running on `localhost:5432`:

```bash
# Option A: Run migration script
python run_migrations.py

# Option B: Manual SQL execution
psql -U postgres -h localhost -d shadow -f migrations/001_create_users_tables.sql
```

Expected tables after migration:
- `users` – User accounts and profiles
- `password_resets` – Password reset tokens
- `auth_logs` – Authentication audit trail
- Indexes for performance optimization

### 3. Configure Environment

Create `.env` file in `shadow-api/`:

```bash
# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=shadow123
DATABASE_NAME=shadow

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# ClickHouse
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=shadow
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=

# JWT/Security
SECRET_KEY=your-secret-key-here-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# ML Service
ML_SERVICE_URL=http://localhost:8001

# CORS
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000

# Logging
LOG_LEVEL=INFO
```

### 4. Run the Server

```bash
# Development with auto-reload
uvicorn app.main:app --reload --port 8000 --host 0.0.0.0

# Production
uvicorn app.main:app --port 8000 --host 0.0.0.0 --workers 4
```

Server will be available at: **http://localhost:8000**

---

## 📋 Required API Endpoints

Your shadow-api should implement these endpoints:

### Authentication
```
POST   /api/v1/auth/login              – Login with credentials
POST   /api/v1/auth/logout             – Logout (invalidate token)
POST   /api/v1/auth/refresh            – Refresh access token
GET    /api/v1/auth/me                 – Get current user info
POST   /api/v1/auth/register           – Register new user (if enabled)
```

### Threats
```
GET    /api/v1/threats                 – List threats (paginated)
GET    /api/v1/threats/:id             – Get threat details
GET    /api/v1/threats/stats           – Get threat statistics
POST   /api/v1/threats/:id/acknowledge – Mark threat as acknowledged
GET    /api/v1/threats/:id/explain     – SHAP explanation for threat
GET    /api/v1/threats/export          – Export threats as CSV
```

### Assets
```
GET    /api/v1/assets                  – List assets (paginated)
GET    /api/v1/assets/:id              – Get asset details
GET    /api/v1/assets/stats            – Get asset statistics
GET    /api/v1/assets/:id/risks        – Get risks for asset
POST   /api/v1/assets                  – Create new asset
PUT    /api/v1/assets/:id              – Update asset
DELETE /api/v1/assets/:id              – Delete asset
GET    /api/v1/assets/export           – Export assets as CSV
```

### ML Service
```
GET    /api/v1/ml/models               – List available models
GET    /api/v1/ml/status               – ML service status
GET    /api/v1/ml/explain/:threatId    – Get model explanation
```

### WebSocket
```
WS     /                               – WebSocket endpoint
Events:
  - threat: {type, threat_id, score, src_ip, dst_ip, severity, timestamp}
  - alert: {type, message, timestamp}
  - system_event: {type, service, message, timestamp}
```

---

## 🔒 Authentication Flow

1. **Login**: User sends credentials to `/auth/login`
   - Response: `{access_token, refresh_token, user}`
   - Tokens stored in localStorage

2. **Authenticated Requests**: Client includes `Authorization: Bearer {token}` header

3. **Token Refresh**: When access token expires (30 min):
   - Client sends refresh token to `/auth/refresh`
   - Response: `{access_token, refresh_token}` (both renewed)
   - Old token invalidated

4. **Logout**: Clear tokens from localStorage, redirect to login

---

## 🔌 WebSocket Events

### Threat Events
```typescript
// New threat detected
{
  type: 'new',
  threat_id: 'uuid',
  score: 0.95,
  src_ip: '192.168.1.100',
  dst_ip: '192.168.1.1',
  severity: 'critical',
  timestamp: '2026-03-23T12:34:56Z'
}

// Threat updated
{
  type: 'update',
  threat_id: 'uuid',
  score: 0.87,
  severity: 'high',
  timestamp: '2026-03-23T12:35:10Z'
}

// Threat resolved
{
  type: 'resolved',
  threat_id: 'uuid',
  timestamp: '2026-03-23T12:40:00Z'
}
```

### Alert Events
```typescript
{
  type: 'critical_activity',
  message: 'Multiple critical threats detected from same source',
  timestamp: '2026-03-23T12:34:56Z'
}
```

### System Events
```typescript
{
  type: 'service_offline',
  service: 'shadow-ingestion',
  message: 'Ingestion service offline for 2 minutes',
  timestamp: '2026-03-23T12:34:56Z'
}
```

---

## 📊 Database Schema

### users table
```sql
id UUID PRIMARY KEY
username TEXT UNIQUE NOT NULL
email TEXT UNIQUE NOT NULL
hashed_password TEXT NOT NULL
role TEXT (admin|analyst|viewer)
org_id TEXT
created_at TIMESTAMPTZ
updated_at TIMESTAMPTZ
is_active BOOLEAN
```

### password_resets table
```sql
id UUID PRIMARY KEY
user_id UUID (FK → users.id)
token TEXT UNIQUE NOT NULL
expires_at TIMESTAMPTZ
created_at TIMESTAMPTZ
```

### auth_logs table
```sql
id BIGSERIAL PRIMARY KEY
username TEXT NOT NULL
success BOOLEAN NOT NULL
ip TEXT
user_agent TEXT
created_at TIMESTAMPTZ
```

---

## 🧪 Testing the Connection

### 1. Test Login
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }'

# Response:
{
  "access_token": "eyJ0eXAiOiJKV1QiLC...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLC...",
  "user": {
    "id": "uuid",
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

### 2. Test Protected Endpoint
```bash
curl -X GET http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer {access_token}"

# Response:
{
  "id": "uuid",
  "username": "admin",
  "email": "admin@example.com",
  "role": "admin",
  "org_id": "default",
  "created_at": "2026-03-23T10:00:00Z",
  "is_active": true
}
```

### 3. Test WebSocket
```bash
# Connect to ws://localhost:8000 with token in auth header
# Should receive connection confirmation
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Verify JWT token is valid and not expired |
| CORS Error | Check ALLOWED_ORIGINS includes frontend URL |
| Database Connection Failed | Verify PostgreSQL is running and credentials are correct |
| WebSocket Connection Fails | Ensure server is running and WS endpoint is correct |
| No Data in Threats | Verify shadow-ingestion is running and sending data |
| ML Service Unavailable | Check shadow-ml is running on port 8001 |

---

## 📁 File Structure

```
shadow-api/
├── app/
│   ├── main.py              – FastAPI app initialization
│   ├── config.py            – Configuration management
│   ├── database.py          – Database connection
│   ├── routes/
│   │   ├── auth.py          – Authentication endpoints
│   │   ├── threats.py       – Threat management
│   │   ├── assets.py        – Asset management
│   │   └── ml.py            – ML integration
│   ├── models/
│   │   ├── user.py          – User data models
│   │   ├── threat.py        – Threat data models
│   │   └── asset.py         – Asset data models
│   ├── services/
│   │   ├── auth.py          – Authentication logic
│   │   ├── jwt.py           – JWT token handling
│   │   └── websocket.py     – WebSocket management
│   └── middleware/
│       ├── cors.py          – CORS configuration
│       └── auth.py          – Auth middleware
├── migrations/
│   └── 001_create_users_tables.sql
├── run_migrations.py        – Migration runner
├── requirements.txt         – Python dependencies
├── .env                     – Environment variables
└── README.md

```

---

## 🚀 Production Deployment

For production, ensure:

1. **Security**:
   - Change default password in `.env`
   - Use environment variables for secrets
   - Enable HTTPS/SSL
   - Set CORS origins carefully

2. **Database**:
   - Use strong authentication
   - Enable SSL for PostgreSQL
   - Regular backups
   - Monitor connection pool

3. **Monitoring**:
   - Enable structured logging
   - Set up alerts
   - Monitor resource usage
   - Track API latency

4. **Scaling**:
   - Use multiple Uvicorn workers
   - Load balance requests
   - Cache with Redis
   - Consider containerization (Docker/Kubernetes)

---

## 📞 Support

For issues or questions:
1. Check backend logs: `tail -f shadow-api.log`
2. Verify all services are running
3. Check database connectivity
4. Review API response codes and error messages
