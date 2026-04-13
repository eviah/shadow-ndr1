# 🐳 Docker Startup Guide

If you're getting `docker-compose: command not found`, follow this guide.

---

## ✅ Quick Fix

Modern Docker uses `docker compose` (without hyphen) instead of `docker-compose`.

All scripts have been updated to use the correct command.

---

## 🚀 Start Databases

### **Option 1: Use Updated Script (RECOMMENDED)**

```powershell
cd c:\Users\liorh\shadow-ndr
.\start-all-services.ps1
```

This will now use the correct `docker compose` command.

### **Option 2: Manual Docker Command**

```powershell
cd c:\Users\liorh\shadow-ndr\deploy

# Start all containers
docker compose up -d

# Wait 30 seconds
Start-Sleep -Seconds 30

# Check status
docker ps
```

### **Option 3: Start Individual Containers**

```powershell
# PostgreSQL
docker run -d --name shadow-postgres \
  -e POSTGRES_PASSWORD=shadow123 \
  -e POSTGRES_DB=shadow \
  -p 5432:5432 \
  postgres:14

# Redis
docker run -d --name shadow-redis \
  -p 6379:6379 \
  redis:7

# ClickHouse
docker run -d --name shadow-clickhouse \
  -p 8123:8123 \
  -p 9000:9000 \
  clickhouse/clickhouse-server

# Kafka
docker run -d --name shadow-kafka \
  -p 9092:9092 \
  -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
  confluentinc/cp-kafka:7.5.0
```

---

## ✅ Verify Docker is Working

```powershell
# Check Docker version
docker --version
# Output: Docker version 20.10+ (should work)

# Check Docker Compose
docker compose version
# Output: Docker Compose version 2.x+

# List running containers
docker ps
# Should show: postgres, redis, clickhouse, kafka (after starting)
```

---

## 🐳 Docker Desktop Installation

If Docker isn't working, install **Docker Desktop**:

1. Download: https://www.docker.com/products/docker-desktop
2. Install and restart computer
3. Open "Docker Desktop" application
4. Wait 30 seconds for it to start
5. Try again: `docker ps`

---

## 🆘 Common Docker Issues

### **Issue: "docker: command not found"**
- Docker Desktop not installed
- **Solution**: Install from https://www.docker.com/products/docker-desktop

### **Issue: "Cannot connect to Docker daemon"**
- Docker Desktop not running
- **Solution**: Open Docker Desktop application and wait for startup

### **Issue: "docker compose: command not found"**
- Old docker-compose command
- **Solution**: All scripts updated to use `docker compose`

### **Issue: "Cannot create container"**
- Port already in use
- **Solution**: `.\troubleshoot.ps1 -KillPorts`

---

## 📊 Check Docker Resources

```powershell
# View all containers (including stopped)
docker ps -a

# View container logs
docker logs shadow-postgres

# View resource usage
docker stats

# Stop all containers
docker compose down

# Remove all containers and data
docker compose down -v
```

---

## ✅ Ready to Start?

```powershell
cd c:\Users\liorh\shadow-ndr
.\start-all-services.ps1
```

All scripts now use the correct `docker compose` command! 🎉
