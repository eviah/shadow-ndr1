# Shadow NDR – Complete System Setup & Running Guide

## 🎯 Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  shadow-ui (React/Vite)                                          │
│  Port: 5173                                                      │
│  URL: http://localhost:5173                                     │
└────────────────────────┬─────────────────────────────────────────┘
                         │ HTTP + WebSocket
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  shadow-api (FastAPI)                                            │
│  Port: 8000                                                      │
│  URL: http://localhost:8000                                     │
└────┬────────────────────┬──────────────┬────────────────────┬────┘
     │                    │              │                    │
     ▼                    ▼              ▼                    ▼
┌─────────────┐  ┌────────────────┐ ┌──────────┐  ┌──────────────┐
│  shadow-ml  │  │  shadow-ing    │ │ClickHouse│  │  PostgreSQL  │
│  (ML)       │  │  estion        │ │(Metrics) │  │  (Auth)      │
│  Port: 8001 │  │  (Ingestion)   │ │Port:8123 │  │  Port: 5432  │
└─────────────┘  │                │ └──────────┘  └──────────────┘
                 │  (Data Pipeline)│
                 └────────────────┘
                 
                 Plus:
                 - Redis (Cache) :6379
                 - PostgreSQL (Data) :5432
```

---

## 📋 Prerequisites Checklist

- [ ] Python 3.10+ installed
- [ ] Node.js 18+ installed
- [ ] Go 1.23+ installed (for shadow-ingestion)
- [ ] PostgreSQL 14+ (or running via Docker)
- [ ] Redis (or running via Docker)
- [ ] ClickHouse (or running via Docker)
- [ ] Git cloned Shadow NDR repository

---

## 🚀 Step-by-Step Startup

### Terminal 1: Start Databases (if using local services)

**PostgreSQL**:
```bash
# Windows (if installed as service)
net start postgresql-x64-14

# macOS
brew services start postgresql

# Linux
sudo systemctl start postgresql

# Or run with Docker:
docker run -d \
  --name shadow-postgres \
  -e POSTGRES_PASSWORD=shadow123 \
  -e POSTGRES_DB=shadow \
  -p 5432:5432 \
  postgres:14
```

**Redis**:
```bash
# Windows (WSL recommended) / macOS / Linux
redis-server --port 6379

# Or with Docker:
docker run -d \
  --name shadow-redis \
  -p 6379:6379 \
  redis:7
```

**ClickHouse**:
```bash
# Docker (recommended)
docker run -d \
  --name shadow-clickhouse \
  -p 8123:8123 \
  -p 9000:9000 \
  clickhouse/clickhouse-server:latest
```

✅ **Databases should be running before proceeding**

---

### Terminal 2: Setup & Run shadow-api

```bash
cd c:\Users\liorh\shadow-ndr\shadow-api

# 1. Create virtual environment
python -m venv venv

# 2. Activate environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run migrations (setup database tables)
python run_migrations.py

# Expected output:
# ✅ Connected to shadow
# ✅ Migration complete: 001_create_users_tables.sql
# ✅ All migrations completed successfully!

# 5. Start the API server
uvicorn app.main:app --reload --port 8000 --host 0.0.0.0

# Server will show:
# INFO:     Uvicorn running on http://0.0.0.0:8000
# INFO:     Application startup complete
```

✅ **Backend ready at http://localhost:8000**

---

### Terminal 3: Run shadow-ml

```bash
cd c:\Users\liorh\shadow-ndr\shadow-ml

# 1. Activate environment (from previous setup)
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 2. Start ML service
uvicorn app.main:app --reload --port 8001 --host 0.0.0.0

# Server will show:
# INFO:     Uvicorn running on http://0.0.0.0:8001
# INFO:     Application startup complete
```

✅ **ML Service ready at http://localhost:8001**

---

### Terminal 4: Run shadow-ingestion

```bash
cd c:\Users\liorh\shadow-ndr\shadow-ingestion

# 1. Start the Go ingestion service
go run main.go

# Or if already built:
./shadow-ingestion.exe  # Windows
./shadow-ingestion      # macOS/Linux

# Expected output:
# shadow-ingestion starting on port 8080...
# Connected to Kafka brokers
# Connected to ClickHouse
# Ready for incoming data
```

✅ **Ingestion service running**

---

### Terminal 5: Run shadow-ui

```bash
cd c:\Users\liorh\shadow-ndr\shadow-ui

# 1. Install dependencies (if not done)
npm install
# or
bun install

# 2. Start development server
npm run dev
# or
bun run dev

# Expected output:
#   VITE v4.x.x  ready in xxx ms
#   ➜  Local:   http://localhost:5173/
#   ➜  press h to show help
```

✅ **Frontend ready at http://localhost:5173**

---

## 🧪 Verification Steps

### 1. Check Backend Connectivity
```bash
# From Terminal 2 logs, should see:
# - FastAPI application startup complete
# - Uvicorn running on http://0.0.0.0:8000
```

### 2. Test API Endpoints
```bash
# Test health endpoint
curl http://localhost:8000/api/v1/auth/me

# Should return 401 (Unauthorized - expected without token)
# Not 502 or connection refused
```

### 3. Check ML Service
```bash
curl http://localhost:8001/health

# Should return 200 OK with health status
```

### 4. Access Frontend
```
Open browser: http://localhost:5173
You should see login page
```

### 5. Test Login
```
Username: admin
Password: admin
(Or use credentials you configured in database)
```

---

## 📊 Verifying Data Flow

### 1. Check Database Connectivity (Terminal 2)
```
shadow-api logs should show:
✅ Database connection successful
✅ PostgreSQL tables initialized
✅ Redis cache connected
```

### 2. Check Ingestion Flow (Terminal 4)
```
shadow-ingestion logs should show:
✅ Kafka consumer connected
✅ ClickHouse connection successful
✅ Processing incoming packets
```

### 3. Monitor Real-time Updates
```
1. Open DevTools (F12) → Network tab
2. Go to http://localhost:5173/threats
3. Should see WebSocket connection to ws://localhost:8000
4. When new threats are detected:
   - WebSocket receives data
   - Dashboard updates in real-time
```

---

## 🔧 Configuration Reference

### shadow-api (.env)
```bash
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
ACCESS_TOKEN_EXPIRE_MINUTES=30

ML_SERVICE_URL=http://localhost:8001

ALLOWED_ORIGINS=http://localhost:5173
```

### shadow-ui (.env)
```bash
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
VITE_ML_URL=http://localhost:8001
VITE_ENV=development
```

### shadow-ingestion (config.yaml)
```yaml
kafka:
  brokers:
    - localhost:9092
  topic: packets
  group_id: shadow-ingestion

clickhouse:
  host: localhost
  port: 8123
  database: shadow

redis:
  host: localhost
  port: 6379

ml:
  url: http://localhost:8001
  timeout: 30s
```

---

## 📈 Monitoring & Logs

### View Real-time Logs

**shadow-api** (Terminal 2):
```
Watch for:
✅ "GET /api/v1/threats HTTP/1.1" 200
✅ "POST /api/v1/auth/login HTTP/1.1" 200
❌ 401 errors (token issues)
❌ 500 errors (backend issues)
```

**shadow-ml** (Terminal 3):
```
Watch for:
✅ Model predictions sent
✅ Feature extraction complete
❌ Timeout errors (slow model)
```

**shadow-ingestion** (Terminal 4):
```
Watch for:
✅ Packets processed
✅ Batch inserted to ClickHouse
✅ ML scoring complete
❌ Kafka connection errors
```

**shadow-ui Browser Console** (F12):
```
Watch for:
✅ API requests (should see Authorization header)
✅ WebSocket connected
❌ CORS errors (backend config issue)
❌ 401 Unauthorized (token issue)
```

---

## 🆘 Troubleshooting

### Issue: "Connection refused" on 8000
**Solution**:
- Verify shadow-api is running in Terminal 2
- Check firewall isn't blocking port 8000
- Ensure PostgreSQL is running

### Issue: "401 Unauthorized" on all requests
**Solution**:
- Verify tokens are stored in localStorage
- Check JWT_ALGORITHM matches in config
- Re-login to get fresh token

### Issue: WebSocket connection fails
**Solution**:
- Check backend CORS configuration
- Verify WS endpoint includes `/socket.io/` path
- Ensure token is valid

### Issue: "No such table: users"
**Solution**:
- Run: `python run_migrations.py`
- Check migration output for errors
- Verify PostgreSQL is running

### Issue: No real-time threat updates
**Solution**:
- Verify shadow-ingestion is running
- Check Kafka is configured correctly
- Monitor ClickHouse for data
- Check WebSocket connection in DevTools

### Issue: "ML service unavailable"
**Solution**:
- Verify shadow-ml is running on port 8001
- Check network connectivity
- Verify configuration points to correct URL

---

## 🚦 Quick Status Check

Run this command to check all services:

```bash
# Windows PowerShell
@(
  ('shadow-api', 'http://localhost:8000/api/v1/auth/me'),
  ('shadow-ml', 'http://localhost:8001/health'),
  ('PostgreSQL', 'localhost:5432'),
  ('Redis', 'localhost:6379')
) | ForEach-Object {
  $name, $url = $_
  try {
    $response = Invoke-WebRequest -Uri $url -TimeoutSec 2 -ErrorAction Stop
    Write-Host "✅ $name is running" -ForegroundColor Green
  } catch {
    Write-Host "❌ $name is not responding" -ForegroundColor Red
  }
}
```

---

## 📝 Initial Setup Checklist

- [ ] Clone repository
- [ ] Install Python 3.10+, Node.js, Go
- [ ] Start PostgreSQL, Redis, ClickHouse
- [ ] Run shadow-api migrations
- [ ] Create admin user in database
- [ ] Start all 5 services in separate terminals
- [ ] Verify all services show "running" status
- [ ] Open http://localhost:5173 in browser
- [ ] Login with admin credentials
- [ ] See dashboard with data
- [ ] Verify WebSocket connection
- [ ] Check real-time updates

---

## 🎉 Success Indicators

When everything is working correctly, you should see:

**Frontend** (http://localhost:5173):
- ✅ Login page loads
- ✅ Can login successfully
- ✅ Dashboard displays threat statistics
- ✅ Real-time updates in threat list
- ✅ No console errors

**Backend** (Terminal 2):
- ✅ "Application startup complete"
- ✅ API requests logged with 200 status
- ✅ No connection errors

**ML Service** (Terminal 3):
- ✅ "Application startup complete"
- ✅ Model initialized
- ✅ Predictions working

**Ingestion** (Terminal 4):
- ✅ Connected to all services
- ✅ Processing packets
- ✅ Sending data to ClickHouse

---

## 🚀 Next Steps

1. **Create more users** in shadow-api dashboard
2. **Configure role-based access** (admin, analyst, viewer)
3. **Set up email notifications** for critical threats
4. **Integrate with SOAR platform** for automated response
5. **Configure threat intelligence feeds**
6. **Setup monitoring and alerting**
7. **Deploy to production** (Docker/Kubernetes)

---

## 📞 Emergency Contacts

If services won't start:
1. Check `.env` files have correct values
2. Verify all prerequisite services running
3. Check firewall rules
4. Review service logs for error messages
5. Ensure ports aren't already in use

**Port Check** (macOS/Linux/Windows PowerShell):
```bash
# Check if port is in use
lsof -i :8000  # or netstat -ano | findstr :8000 on Windows
```

---

## ✅ Ready for Action!

Once all services are running and verified, you have a fully operational Shadow NDR system monitoring your network for threats in real-time!
