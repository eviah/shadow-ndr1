-- Patch RLS policies to handle unset GUCs.
-- PostgreSQL's `current_setting(name, true)` returns '' (empty string) when a
-- custom GUC was never set in the session, NOT NULL. Casting '' to integer
-- raises "invalid input syntax for type integer: ''". That broke the sweeper's
-- connection, which sets app.role='superadmin' but not app.tenant_id.
DROP POLICY IF EXISTS tenant_iso_assets  ON assets;
DROP POLICY IF EXISTS tenant_iso_threats ON threats;
DROP POLICY IF EXISTS tenant_iso_alerts  ON alerts;
DROP POLICY IF EXISTS tenant_iso_risk    ON risk_scores;
DROP POLICY IF EXISTS tenant_iso_audit   ON audit_log;

CREATE POLICY tenant_iso_assets  ON assets
    USING      (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT);

CREATE POLICY tenant_iso_threats ON threats
    USING      (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT);

CREATE POLICY tenant_iso_alerts  ON alerts
    USING      (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT);

CREATE POLICY tenant_iso_risk    ON risk_scores
    USING      (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT);

CREATE POLICY tenant_iso_audit   ON audit_log
    USING      (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INT);
