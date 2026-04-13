# 🎯 Shadow NDR – Quick Reference Card

## 5-Terminal Launch Sequence

```bash
# TERMINAL 1 – Databases
docker run -d --name shadow-postgres -e POSTGRES_PASSWORD=shadow123 -p 5432:5432 postgres:14
docker run -d --name shadow-redis -p 6379:6379 redis:7
docker run -d --name shadow-clickhouse -p 8123:8123 -p 9000:9000 clickhouse/clickhouse-server

# TERMINAL 2 – Backend API
cd shadow-api && venv\Scripts\activate && python run_migrations.py && uvicorn app.main:app --reload --port 8000

# TERMINAL 3 – ML Service  
cd shadow-ml && venv\Scripts\activate && uvicorn app.main:app --reload --port 8001

# TERMINAL 4 – Data Ingestion
cd shadow-ingestion && go run main.go

# TERMINAL 5 – Frontend
cd shadow-ui && npm run dev
```

**Result**: 🟢 All services running on localhost:5173

---

## Service Status

| Service | URL | Port | Status |
|---------|-----|------|--------|
| Frontend | http://localhost:5173 | 5173 | 🟢 |
| Backend API | http://localhost:8000 | 8000 | 🟢 |
| ML Service | http://localhost:8001 | 8001 | 🟢 |
| Ingestion | internal | N/A | 🟢 |
| PostgreSQL | localhost | 5432 | 🟢 |
| Redis | localhost | 6379 | 🟢 |
| ClickHouse | localhost | 8123 | 🟢 |

---

## Database

**Schema**: shadow-api/migrations/001_create_users_tables.sql

**Tables**:
- `users` - Authentication & user info
- `password_resets` - Password reset tokens
- `auth_logs` - Login audit trail

**Migration**:
```bash
python run_migrations.py
```

**Verify**:
```bash
psql -U postgres -d shadow -c "\dt"
```

---

## API Endpoints

### Auth
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/logout` - Logout
- `POST /api/v1/auth/refresh` - Refresh token
- `GET /api/v1/auth/me` - Current user

### Threats
- `GET /api/v1/threats` - List threats
- `GET /api/v1/threats/{id}` - Threat detail
- `GET /api/v1/threats/stats` - Statistics
- `POST /api/v1/threats/{id}/acknowledge` - Acknowledge

### Assets
- `GET /api/v1/assets` - List assets
- `GET /api/v1/assets/{id}` - Asset detail
- `GET /api/v1/assets/stats` - Statistics

### ML
- `GET /api/v1/ml/models` - List models
- `GET /api/v1/ml/status` - Service status

### WebSocket
- `WS /socket.io` - Real-time events

---

## Environment Variables

### shadow-api/.env
```env
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=shadow123
DATABASE_NAME=shadow
REDIS_HOST=localhost
REDIS_PORT=6379
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
```

### shadow-ui/.env
```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
VITE_ML_URL=http://localhost:8001
```

---

## Common Commands

```bash
# Migrations
python run_migrations.py

# Database access
psql -U postgres -d shadow

# View logs
tail -f shadow-api.log

# Test endpoint
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/threats

# Browser console (F12)
# Check WebSocket: window.io
# Check token: localStorage.getItem('access_token')
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Port already in use | Kill process: `lsof -i :8000` then kill |
| PostgreSQL won't connect | Start service: `net start postgresql-x64-14` |
| Token 401 errors | Clear localStorage, re-login |
| WebSocket fails | Check browser DevTools → Network → WS |
| No data in dashboard | Verify ingestion pipeline sending data |

---

## File Structure

```
shadow-ndr/
├── shadow-api/              # FastAPI backend
│   ├── app/routes/          # API endpoints
│   ├── app/services/        # Business logic
│   ├── migrations/          # Database schemas
│   └── requirements.txt
├── shadow-ui/               # React frontend
│   ├── src/services/api/    # API clients
│   ├── src/services/websocket/
│   ├── src/config/
│   └── package.json
├── shadow-ml/               # ML service
├── shadow-ingestion/        # Data pipeline
└── SYSTEM_SETUP_GUIDE.md   # Full setup (this)
```

---

## Tests

```bash
# Backend tests
cd shadow-api && pytest

# Frontend tests
cd shadow-ui && npm test

# Go build
cd shadow-ingestion && go test ./...
```

---

## Version Info

- Python: 3.10+
- Node.js: 18+
- Go: 1.23+
- PostgreSQL: 14+
- FastAPI: 0.104+
- React: 18+

---

Last Updated: 2024
Status: ✅ All systems ready
