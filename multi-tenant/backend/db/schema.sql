-- Shadow NDR Multi-Tenant Schema v2.0
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Tenants ───────────────────────────────────────────────────────────────────
CREATE TABLE tenants (
    id          SERIAL PRIMARY KEY,
    slug        VARCHAR(50)  UNIQUE NOT NULL,
    name        VARCHAR(100) NOT NULL,
    icao_prefix VARCHAR(10),
    plan        VARCHAR(20)  DEFAULT 'pro' CHECK (plan IN ('starter','pro','enterprise')),
    settings    JSONB        DEFAULT '{}',
    active      BOOLEAN      DEFAULT TRUE,
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Users ─────────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    tenant_id     INT         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username      VARCHAR(100) UNIQUE NOT NULL,
    email         VARCHAR(200) UNIQUE,
    password_hash TEXT        NOT NULL,
    role          VARCHAR(20)  DEFAULT 'analyst' CHECK (role IN ('superadmin','admin','analyst','viewer')),
    mfa_enabled   BOOLEAN      DEFAULT FALSE,
    last_login    TIMESTAMPTZ,
    active        BOOLEAN      DEFAULT TRUE,
    created_at    TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_users_tenant  ON users (tenant_id);
CREATE INDEX idx_users_username ON users (username);

-- ── Refresh tokens ────────────────────────────────────────────────────────────
CREATE TABLE refresh_tokens (
    id         SERIAL PRIMARY KEY,
    user_id    INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT         NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ  NOT NULL,
    revoked    BOOLEAN      DEFAULT FALSE,
    created_at TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_rt_user ON refresh_tokens (user_id);
CREATE INDEX idx_rt_hash ON refresh_tokens (token_hash);

-- ── Assets (aircraft, sensors, gateways) ─────────────────────────────────────
CREATE TABLE assets (
    id            SERIAL PRIMARY KEY,
    tenant_id     INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          VARCHAR(150) NOT NULL,
    asset_type    VARCHAR(50)  DEFAULT 'aircraft',
    icao24        VARCHAR(10),
    callsign      VARCHAR(20),
    registration  VARCHAR(20),
    status        VARCHAR(20)  DEFAULT 'active' CHECK (status IN ('active','degraded','offline','compromised')),
    threat_level  VARCHAR(20)  DEFAULT 'safe'   CHECK (threat_level IN ('safe','elevated','warning','critical','under_attack')),
    latitude      DOUBLE PRECISION,
    longitude     DOUBLE PRECISION,
    altitude_ft   INT,
    speed_kts     INT,
    heading       INT,
    squawk        VARCHAR(6)   DEFAULT '1200',
    last_contact  TIMESTAMPTZ,
    location      VARCHAR(100),
    criticality   FLOAT        DEFAULT 0.5 CHECK (criticality BETWEEN 0 AND 1),
    protected     BOOLEAN      DEFAULT TRUE,
    metadata      JSONB        DEFAULT '{}',
    created_at    TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_assets_tenant ON assets (tenant_id);
CREATE INDEX idx_assets_icao24 ON assets (icao24);

-- ── Threats ───────────────────────────────────────────────────────────────────
CREATE TABLE threats (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id        INT          REFERENCES assets(id) ON DELETE SET NULL,
    threat_type     VARCHAR(100) NOT NULL,
    severity        VARCHAR(20)  NOT NULL CHECK (severity IN ('info','low','medium','high','critical','emergency')),
    source_ip       INET,
    dest_ip         INET,
    icao24          VARCHAR(10),
    score           FLOAT        CHECK (score BETWEEN 0 AND 1),
    description     TEXT,
    raw_features    JSONB,
    detector_scores JSONB,
    mitre_technique VARCHAR(20),
    status          VARCHAR(20)  DEFAULT 'active' CHECK (status IN ('active','investigating','resolved','fp')),
    assigned_to     INT          REFERENCES users(id) ON DELETE SET NULL,
    resolved_at     TIMESTAMPTZ,
    detected_at     TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_threats_tenant     ON threats (tenant_id);
CREATE INDEX idx_threats_detected   ON threats (detected_at DESC);
CREATE INDEX idx_threats_severity   ON threats (severity);
CREATE INDEX idx_threats_asset      ON threats (asset_id);
CREATE INDEX idx_threats_status     ON threats (status);

-- ── Alerts ────────────────────────────────────────────────────────────────────
CREATE TABLE alerts (
    id            SERIAL       PRIMARY KEY,
    tenant_id     INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id      INT          REFERENCES assets(id) ON DELETE SET NULL,
    threat_id     UUID         REFERENCES threats(id) ON DELETE CASCADE,
    title         VARCHAR(300) NOT NULL,
    severity      VARCHAR(20)  NOT NULL,
    message       TEXT,
    acknowledged  BOOLEAN      DEFAULT FALSE,
    ack_by        INT          REFERENCES users(id) ON DELETE SET NULL,
    ack_at        TIMESTAMPTZ,
    detected_at   TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_alerts_tenant    ON alerts (tenant_id);
CREATE INDEX idx_alerts_detected  ON alerts (detected_at DESC);
CREATE INDEX idx_alerts_ack       ON alerts (acknowledged);

-- ── Risk scores ───────────────────────────────────────────────────────────────
CREATE TABLE risk_scores (
    id            SERIAL       PRIMARY KEY,
    tenant_id     INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id      INT          REFERENCES assets(id) ON DELETE CASCADE,
    entity_name   VARCHAR(150) NOT NULL,
    risk_score    FLOAT        NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    threat_types  TEXT[],
    calculated_at TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_risk_tenant ON risk_scores (tenant_id, calculated_at DESC);

-- ── Audit log (every significant action) ─────────────────────────────────────
CREATE TABLE audit_log (
    id          SERIAL       PRIMARY KEY,
    tenant_id   INT          REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     INT          REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(100) NOT NULL,
    resource    VARCHAR(50),
    resource_id TEXT,
    details     JSONB        DEFAULT '{}',
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant  ON audit_log (tenant_id, created_at DESC);
CREATE INDEX idx_audit_user    ON audit_log (user_id, created_at DESC);

-- ── Views ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_attack_reports AS
SELECT
    t.id          AS threat_id,
    t.tenant_id,
    t.threat_type,
    t.severity,
    t.description,
    t.mitre_technique,
    t.score,
    t.status      AS threat_status,
    t.detected_at,
    t.resolved_at,
    a.id          AS asset_id,
    a.name        AS aircraft_name,
    a.icao24,
    a.callsign,
    a.registration,
    a.location,
    a.latitude,
    a.longitude,
    a.threat_level AS current_threat_level,
    a.protected,
    a.altitude_ft,
    a.speed_kts,
    u.username    AS assigned_to_name
FROM threats t
LEFT JOIN assets a ON t.asset_id = a.id
LEFT JOIN users u  ON t.assigned_to = u.id;

CREATE OR REPLACE VIEW v_tenant_summary AS
SELECT
    te.id, te.name, te.slug,
    COUNT(DISTINCT u.id)             AS user_count,
    COUNT(DISTINCT a.id)             AS asset_count,
    COUNT(DISTINCT th.id) FILTER (WHERE th.status = 'active') AS active_threats,
    COUNT(DISTINCT al.id) FILTER (WHERE al.acknowledged = FALSE) AS unacked_alerts
FROM tenants te
LEFT JOIN users u   ON u.tenant_id  = te.id
LEFT JOIN assets a  ON a.tenant_id  = te.id
LEFT JOIN threats th ON th.tenant_id = te.id
LEFT JOIN alerts al  ON al.tenant_id = te.id
GROUP BY te.id, te.name, te.slug;
