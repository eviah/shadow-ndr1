# 🚀 Shadow NDR – Complete Startup Guide

**Status**: Services not running yet  
**Next Step**: Follow this guide to start all services

---

## 📋 Overview

You have 6 major services to start in **6 separate terminal windows**:

1. **Databases** (PostgreSQL, Redis, ClickHouse, Kafka)
2. **shadow-api** (Backend REST API)
3. **shadow-ml** (Machine Learning Service)
4. **shadow-ingestion** (Data Pipeline)
5. **shadow-sensor** (Network Sensor)
6. **shadow-ui** (Frontend React App)

---

## 🚀 Startup Instructions

### **TERMINAL 1: Start Databases**

Open a new PowerShell terminal and run:

```powershell
# Docker Compose approach (recommended)
cd c:\Users\liorh\shadow-ndr\deploy
docker-compose up -d

# Or start each service individually:
docker run -d --name shadow-postgres -e POSTGRES_PASSWORD=shadow123 -e POSTGRES_DB=shadow -p 5432:5432 postgres:14
docker run -d --name shadow-redis -p 6379:6379 redis:7
docker run -d --name shadow-clickhouse -p 8123:8123 -p 9000:9000 clickhouse/clickhouse-server
docker run -d --name shadow-kafka -p 9092:9092 -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 confluentinc/cp-kafka:7.5.0
```

⏳ **Wait 30 seconds for databases to initialize**

Verify:
```powershell
docker ps
```

Expected output: 4-5 containers running

---

### **TERMINAL 2: Setup & Run shadow-api**

```powershell
# Set Python path
$env:PATH = "C:\Users\liorh\AppData\Local\Programs\Python\Python312;C:\Users\liorh\AppData\Local\Programs\Python\Python312\Scripts;$env:PATH"

# Navigate to backend
cd c:\Users\liorh\shadow-ndr\shadow-api

# Create virtual environment (if not exists)
if (-not (Test-Path "venv")) {
    python -m venv venv
}

# Activate
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run database migrations
python run_migrations.py

# Expected output:
# ✅ Connected to shadow
# ✅ Migration complete: 001_create_users_tables.sql
# ✅ All migrations completed successfully!

# Start API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

✅ **Server should show**: `Uvicorn running on http://0.0.0.0:8000`

---

### **TERMINAL 3: Run shadow-ml**

```powershell
# Set Python path
$env:PATH = "C:\Users\liorh\AppData\Local\Programs\Python\Python312;C:\Users\liorh\AppData\Local\Programs\Python\Python312\Scripts;$env:PATH"

# Navigate to ML service
cd c:\Users\liorh\shadow-ndr\shadow-ml

# Create virtual environment (if not exists)
if (-not (Test-Path "venv")) {
    python -m venv venv
}

# Activate
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Start ML service
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

✅ **Server should show**: `Uvicorn running on http://0.0.0.0:8001`

---

### **TERMINAL 4: Run shadow-ingestion**

```powershell
# Set Go environment
$env:PATH = "C:\Program Files\Go\bin;$env:PATH"

# Navigate to ingestion
cd c:\Users\liorh\shadow-ndr\shadow-ingestion

# Check if already built
if (Test-Path "shadow-ingestion.exe") {
    # Use existing executable
    .\shadow-ingestion.exe
} else {
    # Build and run
    go build -o shadow-ingestion.exe main.go
    .\shadow-ingestion.exe
}
```

✅ **Should show**: `shadow-ingestion starting on port 8080...`

---

### **TERMINAL 5: Run shadow-sensor**

```powershell
# Set Go environment
$env:PATH = "C:\Program Files\Go\bin;$env:PATH"

# Navigate to sensor
cd c:\Users\liorh\shadow-ndr\shadow-sensor

# Run sensor
go run src/main.rs

# Or if using Go:
cargo run --release
```

✅ **Should show**: `shadow-sensor listening on :9090`

---

### **TERMINAL 6: Run shadow-ui**

```powershell
# Navigate to frontend
cd c:\Users\liorh\shadow-ndr\shadow-ui

# Install dependencies (if not done)
npm install

# Or use Bun (faster)
bun install

# Start development server
npm run dev

# Or with Bun:
bun run dev
```

✅ **Should show**: `Local: http://localhost:5173/`

---

## 🧪 Verify All Services Running

Once all 6 terminals are running, test the integration:

```powershell
# In a 7th terminal
cd c:\Users\liorh\shadow-ndr
.\verify-integration.ps1 -Full
```

Expected output:
```
Services Connected: 7 / 7
API Endpoints: 4 / 4 responding
Files Present: 9 / 9 verified

✅ ALL SERVICES CONNECTED - SYSTEM READY FOR USE
```

---

## 🌐 Access the System

Once verified:

1. **Open Frontend**: http://localhost:5173
2. **Login**: Use default credentials (admin/admin or configured user)
3. **Access Backend Docs**: http://localhost:8000/docs
4. **Check ML Service**: http://localhost:8001/health

---

## 📊 Service Status Checklist

| Service | Port | Command | Status |
|---------|------|---------|--------|
| PostgreSQL | 5432 | `docker ps` | Check running |
| Redis | 6379 | `docker ps` | Check running |
| ClickHouse | 8123 | `docker ps` | Check running |
| Kafka | 9092 | `docker ps` | Check running |
| shadow-api | 8000 | `curl http://localhost:8000/docs` | 🟢 Check |
| shadow-ml | 8001 | `curl http://localhost:8001/health` | 🟢 Check |
| shadow-ingestion | 8080 | Terminal 4 output | 🟢 Check |
| shadow-sensor | 9090 | Terminal 5 output | 🟢 Check |
| shadow-ui | 5173 | Browser: http://localhost:5173 | 🟢 Check |

---

## 🆘 Troubleshooting

### Issue: Port Already in Use
```powershell
# Find process using port (example: 8000)
netstat -ano | findstr :8000

# Kill the process
taskkill /PID <PID> /F
```

### Issue: PostgreSQL Connection Refused
```powershell
# Check if Docker container is running
docker ps | findstr postgres

# If not, start it
docker run -d --name shadow-postgres -e POSTGRES_PASSWORD=shadow123 -e POSTGRES_DB=shadow -p 5432:5432 postgres:14

# Wait 30 seconds then retry
Start-Sleep -Seconds 30
```

### Issue: Python Module Not Found
```powershell
# Make sure venv is activated
venv\Scripts\Activate.ps1

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Issue: Go Build Failed
```powershell
# Clean build cache
go clean -cache

# Re-build
go build -o shadow-ingestion.exe main.go
```

### Issue: npm/Node Issues
```powershell
# Clear npm cache
npm cache clean --force

# Reinstall
npm install

# If using bun:
bun install
```

---

## 📝 Quick Reference Commands

```powershell
# Start Docker containers
docker-compose -f deploy/docker-compose.yml up -d

# Stop Docker containers
docker-compose down

# Check Docker status
docker ps

# View logs for a container
docker logs shadow-postgres

# Check port usage
netstat -ano | findstr :5173

# Kill process
taskkill /PID <PID> /F

# Test API health
curl http://localhost:8000/api/v1/auth/me

# View running Python processes
Get-Process python

# View running Go processes
Get-Process shadow-ingestion
```

---

## ⚠️ Important Notes

1. **Database Wait**: PostgreSQL needs ~30 seconds to initialize after starting
2. **Python Paths**: Make sure Python 3.12+ is installed
3. **Go Version**: Go 1.23+ required
4. **Node Version**: Node 18+ or Bun recommended
5. **Ports**: Ensure all ports (5173, 8000, 8001, 5432, 6379, etc.) are available
6. **Admin Credentials**: Create/configure in database before login

---

## 🎯 Success Indicators

✅ **All services started successfully if you see:**
- Terminal 2: "Application startup complete"
- Terminal 3: "Application startup complete"
- Terminal 4: "Processing packets"
- Terminal 5: "Listening on :9090"
- Terminal 6: "ready in Xms"
- Verification script: "ALL SERVICES CONNECTED"
- Browser: Login page loads at http://localhost:5173

---

## 🚀 Next Steps After Startup

1. Run verification script: `.\verify-integration.ps1 -Full`
2. Open http://localhost:5173 in browser
3. Login with credentials
4. Verify dashboard displays data
5. Check WebSocket connection (DevTools → Network)
6. Monitor logs for errors
7. Access API docs at http://localhost:8000/docs

---

## 📚 Full Documentation

- [SYSTEM_SETUP_GUIDE.md](SYSTEM_SETUP_GUIDE.md) - Complete setup guide
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Quick commands
- [INTEGRATION_STATUS.md](INTEGRATION_STATUS.md) - Integration details
- [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) - Full documentation index

---

**Last Updated**: March 24, 2026  
**Status**: Ready to start services  
**Next**: Follow terminal startup sequence above
