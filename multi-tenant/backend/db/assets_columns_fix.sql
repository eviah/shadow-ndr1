-- Migration: align assets columns with what the routes expect.
-- Adds missing columns and renames `protected` → `is_protected` so queries stop crashing.
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS tail_number  VARCHAR(20),
    ADD COLUMN IF NOT EXISTS airline_code VARCHAR(10);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='assets' AND column_name='protected'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='assets' AND column_name='is_protected'
    ) THEN
        ALTER TABLE assets RENAME COLUMN protected TO is_protected;
    END IF;
END$$;

-- Backfill tail_number from registration where obvious so the UI has something.
UPDATE assets SET tail_number = registration WHERE tail_number IS NULL AND registration IS NOT NULL;
