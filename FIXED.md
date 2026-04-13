# ✅ FIXED: Docker Startup Issue

**Issue**: `docker-compose: The term 'docker-compose' is not recognized`

**Root Cause**: Modern Docker uses `docker compose` (without hyphen)

**Status**: ✅ **ALL SCRIPTS FIXED**

---

## 🔧 What Was Fixed

| Script | Fix | Status |
|--------|-----|--------|
| `start-all-services.ps1` | ✅ Updated to use `docker compose` | Ready |
| `start-all-services.bat` | ✅ Updated to use `docker compose` | Ready |
| `troubleshoot.ps1` | ✅ Updated to use `docker compose` | Ready |
| Documentation | ✅ Updated all references | Ready |

---

## 🚀 NOW TRY THIS

```powershell
cd c:\Users\liorh\shadow-ndr
.\start-all-services.ps1
```

The script will now:
1. ✅ Use `docker compose up -d` (correct command)
2. ✅ Start all 4 database containers
3. ✅ Wait 30 seconds for initialization
4. ✅ Launch all 6 services
5. ✅ Run verification

---

## 📋 Verify Docker Setup First

```powershell
# Check Docker is installed and running
docker --version

# Check Docker Compose is available
docker compose version

# List containers
docker ps
```

If you get errors, see [DOCKER_SETUP.md](DOCKER_SETUP.md)

---

## 🎯 Expected Result

After running `.\start-all-services.ps1`, you should see:

```
[1/6] Starting databases (PostgreSQL, Redis, ClickHouse, Kafka)...
Starting Docker containers...
Databases started. Waiting 30 seconds for initialization...
[2/6] Starting Backend API (shadow-api)...
[3/6] Starting ML Service (shadow-ml)...
[4/6] Starting Data Ingestion (shadow-ingestion)...
[5/6] Starting Network Sensor (shadow-sensor)...
[6/6] Starting Frontend (shadow-ui)...

✅ All services are starting in separate terminals
```

---

## ✨ System Ready!

Once all services start (2 minutes):

- **Frontend**: http://localhost:5173
- **API Docs**: http://localhost:8000/docs
- **Verify**: `.\verify-integration.ps1 -Full`

---

**Date**: March 24, 2026  
**Status**: ✅ Ready to Deploy  
**Next**: Run `.\start-all-services.ps1`
