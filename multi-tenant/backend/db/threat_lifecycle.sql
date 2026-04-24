-- Migration: attack lifecycle fields.
-- `last_seen` tracks the most recent sighting of an ongoing attack so the
-- sweeper can auto-resolve anything that's been quiet for a while.
ALTER TABLE threats
    ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS hit_count INTEGER DEFAULT 1;

UPDATE threats SET last_seen = detected_at WHERE last_seen IS NULL;

CREATE INDEX IF NOT EXISTS idx_threats_active_last_seen
    ON threats (status, last_seen) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_threats_dedupe
    ON threats (tenant_id, asset_id, threat_type, status);
