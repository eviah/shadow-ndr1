# 🚀 Shadow NDR - Complete System Startup

## Quick Start (30 seconds)

### Windows PowerShell (Recommended)
```powershell
cd C:\Users\liorh\shadow-ndr
.\START_ALL_SYSTEMS.ps1
```

### Windows Command Prompt
```cmd
cd C:\Users\liorh\shadow-ndr
START_ALL_SYSTEMS.bat
```

---

## What Gets Started

| System | Port | Type | Status |
|--------|------|------|--------|
| **Main NDR UI** | 3000 | Docker | ✅ |
| **MT APEX API** | 3001 | Node.js | ✅ |
| **Grafana** | 3002 | Docker | ✅ |
| **PostgreSQL** | 5433 | Docker | ✅ |
| **Redis** | 6380 | Docker | ✅ |
| **ClickHouse** | 8123 | Docker | ✅ |
| **Prometheus** | 9091 | Docker | ✅ |
| **Kafka** | 9093 | Docker | ✅ |
| **Sensor (UDP)** | 9999 | Docker | ✅ |

---

## Access Points

Open these in your browser after startup:

- **Main Dashboard**: http://localhost:3000
- **MT APEX**: http://localhost:3001
- **Grafana**: http://localhost:3002 (admin/shadow-investor-2026)
- **Prometheus**: http://localhost:9091

---

## Features Included

✅ **Complete Parser Upgrade** (Phases 0-6)
- 4 ADS-B Type Codes
- 4 Real Protocol Parsers
- 13 Threat Detection Modules
- Sensor binary integration

✅ **Dual-System Architecture**
- Main Shadow NDR (Docker)
- MT APEX Multi-Tenant (Node.js)
- Shared Kafka + PostgreSQL

✅ **Production Ready**
- Full monitoring (Prometheus + Grafana)
- Database persistence
- Real-time analytics

---

## Troubleshooting

### Check if running
```bash
docker-compose ps
```

### View logs
```bash
docker-compose logs -f
```

### Stop everything
```bash
docker-compose down
```

### Check specific port
```bash
netstat -ano | findstr ":3001"
```

---

## More Details

See `STARTUP_GUIDE.md` for:
- Detailed step-by-step guide
- All ports and services
- Testing procedures
- Troubleshooting guide
- Performance optimization
- Database operations
- Advanced commands

---

**Status**: ✅ Production Ready  
**Last Updated**: 2026-04-18
