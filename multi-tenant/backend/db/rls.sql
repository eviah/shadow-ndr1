-- Row-Level Security: tenants can NEVER see each other's data
ALTER TABLE assets      ENABLE ROW LEVEL SECURITY;
ALTER TABLE threats     ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts      ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log   ENABLE ROW LEVEL SECURITY;

-- App role (used by Node.js connection)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shadow_app') THEN
        CREATE ROLE shadow_app;
    END IF;
END$$;

GRANT CONNECT ON DATABASE shadow_ndr_mt TO shadow_app;
GRANT USAGE   ON SCHEMA public           TO shadow_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO shadow_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO shadow_app;

-- RLS policies: current_setting('app.tenant_id') is set per request
CREATE POLICY tenant_iso_assets      ON assets      USING (tenant_id = current_setting('app.tenant_id', TRUE)::INT);
CREATE POLICY tenant_iso_threats     ON threats     USING (tenant_id = current_setting('app.tenant_id', TRUE)::INT);
CREATE POLICY tenant_iso_alerts      ON alerts      USING (tenant_id = current_setting('app.tenant_id', TRUE)::INT);
CREATE POLICY tenant_iso_risk        ON risk_scores USING (tenant_id = current_setting('app.tenant_id', TRUE)::INT);
CREATE POLICY tenant_iso_audit       ON audit_log   USING (tenant_id = current_setting('app.tenant_id', TRUE)::INT);

-- Superadmin bypass
CREATE POLICY superadmin_assets   ON assets      USING (current_setting('app.role', TRUE) = 'superadmin') WITH CHECK (TRUE);
CREATE POLICY superadmin_threats  ON threats     USING (current_setting('app.role', TRUE) = 'superadmin') WITH CHECK (TRUE);
