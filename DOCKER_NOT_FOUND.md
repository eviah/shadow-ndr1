# ⚠️ Docker Not Found - Quick Fix Guide

**Error**: `docker: The term 'docker' is not recognized`

**Cause**: Docker Desktop not installed or not in PATH

---

## ✅ SOLUTION 1: Install Docker Desktop (RECOMMENDED)

### **Step 1: Download Docker Desktop**
- Go to: https://www.docker.com/products/docker-desktop
- Click "Download for Windows"
- Run the installer

### **Step 2: Install**
- Accept license agreement
- Choose installation location
- Check "Add Docker to PATH" during installation
- Restart your computer when prompted

### **Step 3: Verify Installation**
```powershell
docker --version
# Output: Docker version 24.x.x (or similar)

docker ps
# Output: (empty list of containers)
```

### **Step 4: Start Services**
```powershell
cd c:\Users\liorh\shadow-ndr
.\start-all-services.ps1
```

---

## ✅ SOLUTION 2: Manual Startup (No Docker Needed)

If you don't want to install Docker, start services manually:

### **Terminal 1: Start Databases Separately**

**PostgreSQL** (install locally or skip if not needed)
```powershell
# If PostgreSQL is installed locally:
psql -U postgres -c "CREATE DATABASE shadow;"
```

**Redis** (install locally or skip)
```powershell
# If Redis is installed:
redis-server --port 6379
```

### **Terminal 2: Backend API**
```powershell
$env:PATH = "C:\Users\liorh\AppData\Local\Programs\Python\Python312;C:\Users\liorh\AppData\Local\Programs\Python\Python312\Scripts;$env:PATH"

cd c:\Users\liorh\shadow-ndr\shadow-api

if (-not (Test-Path 'venv')) { python -m venv venv }
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt -q

# Skip migrations if no PostgreSQL
# python run_migrations.py

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### **Terminal 3: ML Service**
```powershell
$env:PATH = "C:\Users\liorh\AppData\Local\Programs\Python\Python312;C:\Users\liorh\AppData\Local\Programs\Python\Python312\Scripts;$env:PATH"

cd c:\Users\liorh\shadow-ndr\shadow-ml

if (-not (Test-Path 'venv')) { python -m venv venv }
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt -q

uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

### **Terminal 4: Frontend**
```powershell
cd c:\Users\liorh\shadow-ndr\shadow-ui

npm install

npm run dev
```

---

## ✅ SOLUTION 3: Quick Docker Setup Check

Run this to see what's missing:

```powershell
# Check if Docker is installed
Get-Command docker -ErrorAction SilentlyContinue

# If not found, Docker is not installed
# Solution: Install Docker Desktop (see Solution 1 above)

# Check PATH
$env:PATH -split ";" | findstr -i docker

# If empty, Docker not in PATH
# Solution: Reinstall Docker and check "Add Docker to PATH"
```

---

## ✅ SOLUTION 4: Add Docker to PATH Manually

If Docker is installed but not in PATH:

```powershell
# Find Docker installation
dir "C:\Program Files\Docker"
dir "C:\Program Files (x86)\Docker"

# If found, add to PATH
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"

# Verify
docker --version
```

---

## 📊 Recommended: Use Docker

Docker makes it much easier because:
- ✅ No need to install PostgreSQL, Redis, ClickHouse locally
- ✅ All services run in containers
- ✅ Easy to start/stop/reset
- ✅ No port conflicts with other applications
- ✅ One command: `docker compose up -d`

---

## 🚀 Next Steps

### **If Installing Docker:**
1. Download and install Docker Desktop
2. Restart computer
3. Run: `.\start-all-services.ps1`
4. Done! ✅

### **If Using Manual Startup:**
1. Open 4 terminals
2. Follow Terminal 1-4 commands above
3. Open http://localhost:5173
4. Done! ✅

---

## 🆘 Troubleshooting

### **"Docker command works but containers won't start"**
- Make sure Docker Desktop app is running (check system tray)
- Restart Docker Desktop if needed

### **"Still getting 'docker not found' after reinstall"**
- Restart PowerShell/CMD
- Or restart computer
- Then try: `docker --version`

### **"Prefer not to use Docker"**
- Follow Solution 2 (Manual Startup) above
- You'll need to install PostgreSQL, Redis locally
- Or skip them if not needed for testing

---

## 📋 Quick Checklist

- [ ] Docker Desktop downloaded and installed
- [ ] Computer restarted
- [ ] `docker --version` shows version number
- [ ] `docker ps` shows empty container list
- [ ] Ready to run: `.\start-all-services.ps1`

---

**Status**: Ready to fix Docker issue  
**Next**: Choose Solution 1, 2, 3, or 4 above

