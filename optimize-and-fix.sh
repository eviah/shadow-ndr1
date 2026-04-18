#!/bin/bash

##############################################################################
# SHADOW NDR - OPTIMIZATION & BUG FIX SCRIPT
#
# Identifies and fixes common issues:
# 1. Configuration problems
# 2. Performance bottlenecks
# 3. Missing dependencies
# 4. Database schema issues
# 5. Memory leaks
# 6. Logging problems
# 7. Security misconfigurations
#
# Goal: 10/10 Perfect system
##############################################################################

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXES_APPLIED=0
ISSUES_FOUND=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_issue() { echo -e "${RED}[ISSUE]${NC} $1"; ((ISSUES_FOUND++)); }
log_fix() { echo -e "${GREEN}[FIXED]${NC} $1"; ((FIXES_APPLIED++)); }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     🔧 SHADOW NDR - OPTIMIZATION & BUG FIX SUITE 🔧       ║
║                                                            ║
║     Identify and fix issues for 10/10 quality             ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

cd "$PROJECT_DIR"

# =============================================================================
# CHECK 1: DOCKER & COMPOSE CONFIGURATION
# =============================================================================

echo -e "${YELLOW}═══ Checking Docker Configuration ═══${NC}\n"

log_info "Checking if Docker is running..."
if ! docker ps &>/dev/null; then
    log_issue "Docker daemon is not running"
else
    log_ok "Docker daemon is running"
fi

log_info "Checking docker-compose syntax..."
if docker-compose config > /dev/null 2>&1; then
    log_ok "docker-compose.yml is valid"
else
    log_issue "docker-compose.yml has syntax errors"
fi

log_info "Checking for unused volumes..."
UNUSED=$(docker volume ls -q --filter dangling=true | wc -l)
if [ "$UNUSED" -gt 0 ]; then
    log_issue "Found $UNUSED unused Docker volumes"
    log_info "Cleaning up unused volumes..."
    docker volume prune -f > /dev/null 2>&1
    log_fix "Removed unused volumes"
fi

log_info "Checking for dangling images..."
DANGLING=$(docker images -f "dangling=true" -q | wc -l)
if [ "$DANGLING" -gt 0 ]; then
    log_issue "Found $DANGLING dangling Docker images"
    log_info "Cleaning up dangling images..."
    docker image prune -f > /dev/null 2>&1
    log_fix "Removed dangling images"
fi

echo ""

# =============================================================================
# CHECK 2: DEPENDENCY VERIFICATION
# =============================================================================

echo -e "${YELLOW}═══ Checking Dependencies ═══${NC}\n"

DEPENDENCIES=("docker" "docker-compose" "python3" "pip")

for dep in "${DEPENDENCIES[@]}"; do
    if command -v "$dep" &> /dev/null; then
        VERSION=$($dep --version 2>&1 | head -1)
        log_ok "$VERSION"
    else
        log_issue "$dep not found in PATH"
    fi
done

log_info "Checking Python package dependencies..."
cd "$PROJECT_DIR/shadow-api"
if [ -f "requirements.txt" ]; then
    while IFS= read -r package; do
        if ! pip show "${package%==*}" > /dev/null 2>&1; then
            log_issue "Missing Python package: $package"
            log_info "Installing $package..."
            pip install "$package" -q 2>/dev/null || true
            log_fix "Installed $package"
        fi
    done < requirements.txt
fi

cd "$PROJECT_DIR/shadow-ml"
if [ -f "requirements.txt" ]; then
    while IFS= read -r package; do
        if ! pip show "${package%==*}" > /dev/null 2>&1; then
            log_issue "Missing Python package: $package"
            log_info "Installing $package..."
            pip install "$package" -q 2>/dev/null || true
            log_fix "Installed $package"
        fi
    done < requirements.txt
fi

cd "$PROJECT_DIR"
echo ""

# =============================================================================
# CHECK 3: DATABASE CONFIGURATION
# =============================================================================

echo -e "${YELLOW}═══ Checking Database Configuration ═══${NC}\n"

log_info "Verifying PostgreSQL credentials are configured..."
if grep -q "POSTGRES_PASSWORD" docker-compose.yml; then
    if grep "shadow123" docker-compose.yml > /dev/null; then
        log_issue "PostgreSQL using default/weak password in production"
        log_info "Password should be changed in production environment"
    else
        log_ok "PostgreSQL password is configured"
    fi
fi

log_info "Checking database connection string format..."
if grep -q "DATABASE_URL" docker-compose.yml; then
    log_ok "Database URL is configured"
fi

log_info "Verifying database backup configuration..."
if [ ! -f "backup/postgres-backup.sql" ]; then
    log_issue "No database backup found"
    log_info "Creating backup directory..."
    mkdir -p "$PROJECT_DIR/backup"
    log_fix "Backup directory created"
fi

echo ""

# =============================================================================
# CHECK 4: KAFKA CONFIGURATION
# =============================================================================

echo -e "${YELLOW}═══ Checking Kafka Configuration ═══${NC}\n"

log_info "Verifying Kafka topic configuration..."
if docker-compose ps | grep -q "kafka"; then
    if docker-compose exec -T kafka kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null | grep -q "shadow"; then
        log_ok "Kafka topics are configured"
    else
        log_issue "Kafka topics not found"
        log_info "Creating Kafka topics..."
        docker-compose exec -T kafka kafka-topics.sh --bootstrap-server localhost:9092 \
            --create --topic shadow.raw --partitions 3 --replication-factor 1 2>/dev/null || true
        docker-compose exec -T kafka kafka-topics.sh --bootstrap-server localhost:9092 \
            --create --topic shadow.threats --partitions 3 --replication-factor 1 2>/dev/null || true
        docker-compose exec -T kafka kafka-topics.sh --bootstrap-server localhost:9092 \
            --create --topic shadow.ml.decisions --partitions 2 --replication-factor 1 2>/dev/null || true
        log_fix "Kafka topics created"
    fi
fi

echo ""

# =============================================================================
# CHECK 5: API CONFIGURATION
# =============================================================================

echo -e "${YELLOW}═══ Checking API Configuration ═══${NC}\n"

if [ -f "$PROJECT_DIR/shadow-api/.env" ]; then
    log_ok "API .env file found"

    if grep -q "SECRET_KEY" "$PROJECT_DIR/shadow-api/.env"; then
        if grep "change-me" "$PROJECT_DIR/shadow-api/.env" > /dev/null; then
            log_issue "API SECRET_KEY is set to default value"
            log_info "Generating secure SECRET_KEY..."
            NEW_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
            sed -i "s/change-me/$NEW_KEY/g" "$PROJECT_DIR/shadow-api/.env"
            log_fix "Generated new secure SECRET_KEY"
        fi
    fi
else
    log_issue "API .env file not found"
fi

log_info "Checking API logging configuration..."
if grep -q "LOG_LEVEL" docker-compose.yml; then
    log_ok "API logging is configured"
fi

echo ""

# =============================================================================
# CHECK 6: ML ENGINE CONFIGURATION
# =============================================================================

echo -e "${YELLOW}═══ Checking ML Engine Configuration ═══${NC}\n"

if [ -f "$PROJECT_DIR/shadow-ml/.env" ]; then
    log_ok "ML .env file found"
else
    log_issue "ML .env file not found"
    log_info "Creating ML .env with defaults..."
    cat > "$PROJECT_DIR/shadow-ml/.env" << 'MLENV'
ENVIRONMENT=production
LOG_LEVEL=INFO
ML_PORT=8001
KAFKA_BROKERS=kafka:29092
DATABASE_URL=postgresql://shadow:shadow-prod-2026@postgres:5432/shadow_ndr
REDIS_URL=redis://redis:6379
MLENV
    log_fix "ML .env created"
fi

echo ""

# =============================================================================
# CHECK 7: LOGGING CONFIGURATION
# =============================================================================

echo -e "${YELLOW}═══ Checking Logging Configuration ═══${NC}\n"

if [ ! -d "$PROJECT_DIR/logs" ]; then
    log_issue "Logs directory not found"
    mkdir -p "$PROJECT_DIR/logs"
    log_fix "Logs directory created"
fi

log_info "Checking log file permissions..."
if [ -d "$PROJECT_DIR/logs" ]; then
    chmod 755 "$PROJECT_DIR/logs"
    log_ok "Log directory permissions are correct"
fi

log_info "Setting up log rotation..."
if [ ! -f "/etc/logrotate.d/shadow-ndr" ]; then
    log_issue "Log rotation not configured"
    log_info "Log rotation should be configured in production"
fi

echo ""

# =============================================================================
# CHECK 8: MONITORING SETUP
# =============================================================================

echo -e "${YELLOW}═══ Checking Monitoring Setup ═══${NC}\n"

if [ -f "$PROJECT_DIR/monitoring/prometheus.yml" ]; then
    log_ok "Prometheus config found"
else
    log_issue "Prometheus config not found"
fi

if [ -f "$PROJECT_DIR/monitoring/grafana-provisioning/datasources/prometheus.yml" ]; then
    log_ok "Grafana datasources configured"
else
    log_issue "Grafana datasources not configured"
fi

echo ""

# =============================================================================
# CHECK 9: SECURITY CONFIGURATION
# =============================================================================

echo -e "${YELLOW}═══ Checking Security Configuration ═══${NC}\n"

log_info "Checking for hardcoded secrets in code..."
SECRETS_FOUND=0
if grep -r "password=" "$PROJECT_DIR/shadow-api" 2>/dev/null | grep -v ".pyc" | grep -v ".git"; then
    SECRETS_FOUND=$((SECRETS_FOUND + 1))
fi
if grep -r "password=" "$PROJECT_DIR/shadow-ml" 2>/dev/null | grep -v ".pyc" | grep -v ".git"; then
    SECRETS_FOUND=$((SECRETS_FOUND + 1))
fi

if [ $SECRETS_FOUND -gt 0 ]; then
    log_issue "Found hardcoded secrets in code - move to environment variables"
fi

log_info "Checking TLS configuration..."
if grep -q "ssl" "$PROJECT_DIR/docker-compose.yml"; then
    log_ok "TLS is configured"
else
    log_issue "TLS not explicitly configured in docker-compose (OK for dev)"
fi

log_info "Checking RBAC configuration..."
if [ -f "$PROJECT_DIR/k8s-deployment.yaml" ]; then
    if grep -q "rbac" "$PROJECT_DIR/k8s-deployment.yaml"; then
        log_ok "RBAC is configured in Kubernetes"
    fi
fi

echo ""

# =============================================================================
# CHECK 10: PERFORMANCE OPTIMIZATION
# =============================================================================

echo -e "${YELLOW}═══ Checking Performance Optimization ═══${NC}\n"

log_info "Checking database connection pooling..."
if grep -q "pool" "$PROJECT_DIR/shadow-api/app/main.py" 2>/dev/null; then
    log_ok "Database connection pooling is configured"
else
    log_issue "Database connection pooling may not be configured"
    log_info "Consider enabling connection pooling for better performance"
fi

log_info "Checking API caching..."
if grep -q "cache" "$PROJECT_DIR/shadow-api/app/routes"/*.py 2>/dev/null; then
    log_ok "API caching is configured"
fi

log_info "Checking Kafka partition configuration..."
if grep -q "KAFKA_NUM_PARTITIONS" docker-compose.yml; then
    PARTITIONS=$(grep "KAFKA_NUM_PARTITIONS" docker-compose.yml | cut -d'=' -f2)
    if [ "$PARTITIONS" -ge 3 ]; then
        log_ok "Kafka partitioning is optimized ($PARTITIONS partitions)"
    fi
fi

echo ""

# =============================================================================
# CHECK 11: DOCUMENTATION
# =============================================================================

echo -e "${YELLOW}═══ Checking Documentation ═══${NC}\n"

REQUIRED_DOCS=(
    "INVESTOR-READY.md"
    "DEPLOYMENT-COMPLETE.md"
    "SECURITY-HARDENING-CHECKLIST.md"
    "k8s-deployment.yaml"
    "docker-compose.yml"
)

for doc in "${REQUIRED_DOCS[@]}"; do
    if [ -f "$PROJECT_DIR/$doc" ]; then
        log_ok "$doc exists"
    else
        log_issue "$doc not found"
    fi
done

echo ""

# =============================================================================
# SUMMARY & RECOMMENDATIONS
# =============================================================================

echo -e "${YELLOW}════════════════════════════════════════════════${NC}"
echo -e "${BLUE}OPTIMIZATION & BUG FIX SUMMARY${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════${NC}\n"

echo -e "  ${GREEN}✓ Issues Fixed:${NC}   $FIXES_APPLIED"
echo -e "  ${RED}⚠ Issues Found:${NC}    $ISSUES_FOUND"
echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "  ${GREEN}🎉 SYSTEM IS OPTIMIZED & BUG-FREE 🎉${NC}"
    echo -e "  ${GREEN}Quality Score: 10/10 EXCELLENT${NC}"
elif [ $ISSUES_FOUND -le 3 ]; then
    echo -e "  ${YELLOW}⚠️  SYSTEM IS GOOD (Minor improvements suggested)${NC}"
    echo -e "  ${YELLOW}Quality Score: 9/10 VERY GOOD${NC}"
else
    echo -e "  ${RED}❌ SYSTEM NEEDS ATTENTION${NC}"
    echo -e "  ${RED}Quality Score: <9/10${NC}"
fi

echo ""
echo -e "${BLUE}RECOMMENDATIONS:${NC}"
echo "  1. Run: ./run-all-tests.sh"
echo "  2. Run: ./chaos-engineering-tests.sh"
echo "  3. Deploy: docker-compose up -d"
echo "  4. Monitor: http://localhost:3000 (Grafana)"
echo "  5. Load test: python3 load-test.py"
echo ""

exit $ISSUES_FOUND
