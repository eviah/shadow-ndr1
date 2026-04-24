-- Migration: fill columns that auth.js expects but schema.sql doesn't define.

-- refresh_tokens: login flow inserts richer fields than the minimal seed schema.
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS tenant_id  INT REFERENCES tenants(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS ip_address INET,
    ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- users: login flow tracks login_count; schema.sql only has last_login.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS login_count INT DEFAULT 0;

-- tenants: login response + JWT include brand_color (used by frontend theming).
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS brand_color VARCHAR(16) DEFAULT '#0ea5e9';

-- Seed airline brand colors so the UI picks up distinct themes per tenant.
UPDATE tenants SET brand_color = '#003399' WHERE slug = 'elal';    -- EL AL navy
UPDATE tenants SET brand_color = '#e11d48' WHERE slug = 'israir';  -- Israir red
UPDATE tenants SET brand_color = '#f97316' WHERE slug = 'arkia';   -- Arkia orange
