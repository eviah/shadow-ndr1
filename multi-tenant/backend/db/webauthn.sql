-- FIDO2 / WebAuthn credential storage for step-up auth on destructive ops.
-- Apply with: docker exec -i shadow-postgres psql -U shadow -d shadow_ndr_mt < webauthn.sql

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  credential_id   TEXT    NOT NULL UNIQUE,
  public_key      BYTEA   NOT NULL,
  counter         BIGINT  NOT NULL DEFAULT 0,
  transports      TEXT[]  NOT NULL DEFAULT '{}',
  device_type     TEXT,
  backed_up       BOOLEAN NOT NULL DEFAULT FALSE,
  nickname        TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_webauthn_user_id  ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_tenant   ON webauthn_credentials(tenant_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge       TEXT PRIMARY KEY,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose         TEXT NOT NULL,                -- 'register' | 'stepup:<op>'
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webauthn_chal_expires ON webauthn_challenges(expires_at);
