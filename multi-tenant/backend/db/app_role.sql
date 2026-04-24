-- Create a non-superuser app role so FORCE ROW LEVEL SECURITY actually fires.
-- Superusers and BYPASSRLS roles skip all policies, which is why the previous
-- shadow connection leaked tenants across each other.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'shadow_app') THEN
        CREATE ROLE shadow_app LOGIN PASSWORD 'aPxZ74iYUA4-QRcMW_LFutNUpYnqwUZ1'
            NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
    END IF;
END$$;

GRANT CONNECT ON DATABASE shadow_ndr_mt TO shadow_app;
GRANT USAGE ON SCHEMA public TO shadow_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON
    tenants, users, assets, threats, alerts, risk_scores, audit_log, refresh_tokens
TO shadow_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO shadow_app;

-- Future tables/sequences: keep the app role in sync automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO shadow_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO shadow_app;
