-- ============================================================
--  Additive schema — safe to run repeatedly on existing DBs
--  (Full bootstrap remains migration.sql for empty databases.)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DO $$
BEGIN
CREATE TYPE scan_source AS ENUM ('extension', 'web', 'mcp', 'api', 'cli', 'unknown');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'scans' AND column_name = 'source'
  ) THEN
    ALTER TABLE scans ADD COLUMN source scan_source NOT NULL DEFAULT 'unknown';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'scans' AND column_name = 'project_hash'
  ) THEN
    ALTER TABLE scans ADD COLUMN project_hash VARCHAR(64);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_scans_project_hash ON scans(project_hash) WHERE project_hash IS NOT NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scan_source') THEN
    BEGIN
      ALTER TYPE scan_source ADD VALUE IF NOT EXISTS 'mcp';
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS project_usage (
  id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  project_hash VARCHAR(64)  NOT NULL,
  user_id      UUID         REFERENCES users(id) ON DELETE CASCADE,
  session_id   VARCHAR(64),
  scan_count   INTEGER      NOT NULL DEFAULT 0,
  updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  CONSTRAINT project_usage_one_actor CHECK (
    (user_id IS NOT NULL AND session_id IS NULL)
    OR (user_id IS NULL AND session_id IS NOT NULL)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_project_usage_project_user
  ON project_usage (project_hash, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_project_usage_project_session
  ON project_usage (project_hash, session_id) WHERE user_id IS NULL AND session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_project_usage_project ON project_usage(project_hash);

-- ── waitlist_signups (marketing landing) ─────────────────────
CREATE TABLE IF NOT EXISTS waitlist_signups (
  id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  email      VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
  CONSTRAINT waitlist_signups_email_unique UNIQUE (email)
);
CREATE INDEX IF NOT EXISTS idx_waitlist_created ON waitlist_signups(created_at);
