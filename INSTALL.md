# Shadow NDR - Installation Guide

## Project Overview
Shadow NDR is an aviation cybersecurity system with components in Rust, Python, Go, and TypeScript.

## ✅ Completed Installations

### 1. Rust Components (✅ READY)

#### shadow-parsers (Release Build ✅)
- **Status**: Built and tested (24/24 tests passing)
- **Location**: `shadow-parsers/target/release/`
- **Features**: 
  - IEC 104 protocol parser (45 type IDs)
  - Streaming parser with buffer pooling
  - Aviation safety criticality detection
  - Zero-copy parsing with nom

Build command:
```bash
cd shadow-parsers
cargo build --release
```

#### shadow-sensor (⚠️ Requires system dependencies)
- **Status**: Partial (requires librdkafka system libs)
- **Dependencies needed**: 
  - librdkafka (Kafka C client library)
  - Visual Studio Build Tools (Windows)
- **Features**:
  - Real-time packet capture (WinPcap/Npcap)
  - IEC 104 parsing and enrichment
  - Prometheus metrics export
  - Kafka producer integration

Install librdkafka:
```powershell
# Windows - Using vcpkg (recommended)
vcpkg install librdkafka:x64-windows

# Or build from source
# https://github.com/edenhill/librdkafka/wiki/Build-instructions
```

### 2. Python Components (✅ Environments Ready)

#### shadow-ml (✅ Dependencies Installed)
- **Python**: 3.13.12
- **Packages installed**:
  - scikit-learn (ML models)
  - pandas, numpy (Data processing)
  - matplotlib (Visualization)
  - flask (API server)
  - pytest (Testing)
  - requests, python-dotenv (Utilities)

#### shadow-api (Ready for installation)
- **Python**: 3.10.11
- **Recommended packages**:
  - flask, flask-restx (REST API)
  - sqlalchemy (ORM)
  - psycopg2-binary (PostgreSQL driver)
  - pydantic (Data validation)
  - pytest (Testing)

Install with:
```bash
cd shadow-api
pip install flask flask-restx sqlalchemy psycopg2-binary pydantic pytest
```

### 3. Other Components

#### shadow-ingestion (Go)
- **Status**: Source code present but empty (main.go)
- **Usage**: Kafka consumer for IEC 104 events
- **Build when ready**: `go build -o shadow-ingestion ./shadow-ingestion`

#### shadow-ui (TypeScript/React)
- **Status**: Source structure present
- **Setup when ready**:
```bash
cd shadow-ui
npm install
npm run dev
```

#### deploy (Docker Compose)
- **Status**: Configuration ready in `deploy/docker-compose.yml`
- **Services**: All microservices ready to containerize

## 📊 Installation Status Summary

| Component | Language | Status | Build | Tests |
|-----------|----------|--------|-------|-------|
| shadow-parsers | Rust | ✅ Ready | ✅ Release | ✅ 24/24 |
| shadow-sensor | Rust | ⚠️ Needs libs | ⏳ Pending | N/A |
| shadow-ml | Python | ✅ Ready | ✅ Env | N/A |
| shadow-api | Python | ⏳ Ready | ⏳ To do | N/A |
| shadow-ingestion | Go | ⏳ Empty | N/A | N/A |
| shadow-ui | TypeScript | ⏳ Ready | N/A | N/A |
| deploy | Docker | ✅ Ready | N/A | N/A |

## 🚀 Quick Start Commands

### Test All Installations
```powershell
# Rust tests
cd shadow-parsers
cargo test --lib

# Python environments verified
python --version  # For shadow-api (3.10.11)
python3.13 --version  # For shadow-ml (3.13.12)
```

### Build Release Binaries
```powershell
# shadow-parsers (complete)
cd shadow-parsers
cargo build --release

# shadow-sensor (pending librdkafka)
cd shadow-sensor
# Install librdkafka first, then:
cargo build --release
```

### Run Tests
```powershell
cd shadow-parsers
cargo test --lib  # 20 unit tests
cargo test --doc  # 4 doctests
```

## 📋 Next Steps

1. **Install librdkafka** for shadow-sensor (Windows/macOS/Linux specific)
2. **Build shadow-sensor** release binary
3. **Install shadow-api** Python dependencies
4. **Configure docker-compose** environment
5. **Deploy services** with Docker

## 🔧 System Requirements

- **Rust**: 1.80+ (installed ✅)
- **Python**: 3.10+ (installed ✅ - both 3.10.11 and 3.13.12)
- **Windows**: 
  - Visual Studio Build Tools (for C dependencies)
  - WinPcap or Npcap (for packet capture)
- **Package managers**: 
  - cargo (Rust)
  - pip (Python)
  - npm (Node.js, when needed)

## 📞 Support

For installation issues:
- Check Rust docs: https://www.rust-lang.org/tools/install
- Check Python venv docs: https://docs.python.org/3/library/venv.html
- Check Kafka docs: https://kafka.apache.org/
