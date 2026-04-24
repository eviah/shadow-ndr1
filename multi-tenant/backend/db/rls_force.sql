-- Migration: force RLS on tenant tables and tighten policies.
-- Apply against an existing DB that has already run schema.sql + rls.sql.
--
-- Why: the node connection is the table owner. Postgres skips RLS for owners
-- unless FORCE ROW LEVEL SECURITY is set. Without this, `db.tenantQuery()`'s
-- GUCs are ignored and tenants leak across each other.

ALTER TABLE assets      FORCE ROW LEVEL SECURITY;
ALTER TABLE threats     FORCE ROW LEVEL SECURITY;
ALTER TABLE alerts      FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_scores FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log   FORCE ROW LEVEL SECURITY;

-- Replace the existing policies with ones that also enforce WITH CHECK on writes,
-- so cross-tenant INSERT/UPDATE is rejected the same way SELECT is.
DROP POLICY IF EXISTS tenant_iso_assets  ON assets;
DROP POLICY IF EXISTS tenant_iso_threats ON threats;
DROP POLICY IF EXISTS tenant_iso_alerts  ON alerts;
DROP POLICY IF EXISTS tenant_iso_risk    ON risk_scores;
DROP POLICY IF EXISTS tenant_iso_audit   ON audit_log;

CREATE POLICY tenant_iso_assets  ON assets
    USING      (tenant_id = current_setting('app.tenant_id', TRUE)::INT)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE)::INT);

CREATE POLICY tenant_iso_threats ON threats
    USING      (tenant_id = current_setting('app.tenant_id', TRUE)::INT)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE)::INT);

CREATE POLICY tenant_iso_alerts  ON alerts
    USING      (tenant_id = current_setting('app.tenant_id', TRUE)::INT)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE)::INT);

CREATE POLICY tenant_iso_risk    ON risk_scores
    USING      (tenant_id = current_setting('app.tenant_id', TRUE)::INT)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE)::INT);

CREATE POLICY tenant_iso_audit   ON audit_log
    USING      (tenant_id = current_setting('app.tenant_id', TRUE)::INT)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE)::INT);

-- Superadmin bypass across every tenant table (rls.sql only had assets+threats).
DROP POLICY IF EXISTS superadmin_assets   ON assets;
DROP POLICY IF EXISTS superadmin_threats  ON threats;
DROP POLICY IF EXISTS superadmin_alerts   ON alerts;
DROP POLICY IF EXISTS superadmin_risk     ON risk_scores;
DROP POLICY IF EXISTS superadmin_audit    ON audit_log;

CREATE POLICY superadmin_assets  ON assets
    USING      (current_setting('app.role', TRUE) = 'superadmin')
    WITH CHECK (current_setting('app.role', TRUE) = 'superadmin');

CREATE POLICY superadmin_threats ON threats
    USING      (current_setting('app.role', TRUE) = 'superadmin')
    WITH CHECK (current_setting('app.role', TRUE) = 'superadmin');

CREATE POLICY superadmin_alerts  ON alerts
    USING      (current_setting('app.role', TRUE) = 'superadmin')
    WITH CHECK (current_setting('app.role', TRUE) = 'superadmin');

CREATE POLICY superadmin_risk    ON risk_scores
    USING      (current_setting('app.role', TRUE) = 'superadmin')
    WITH CHECK (current_setting('app.role', TRUE) = 'superadmin');

CREATE POLICY superadmin_audit   ON audit_log
    USING      (current_setting('app.role', TRUE) = 'superadmin')
    WITH CHECK (current_setting('app.role', TRUE) = 'superadmin');
