-- ============================================================
--  Vibesecur — Database Schema Migration v1.0
--  PostgreSQL 15 · Run via: psql $DATABASE_URL -f migration.sql
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── users ────────────────────────────────────────────────────
CREATE TYPE user_plan AS ENUM ('free','solo','pro','admin');

CREATE TABLE IF NOT EXISTS users (
  id                     UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
  email                  VARCHAR(255)   UNIQUE NOT NULL,
  password_hash          VARCHAR(255)   NOT NULL,
  plan                   user_plan      NOT NULL DEFAULT 'free',
  stripe_customer_id     VARCHAR(100),
  stripe_subscription_id VARCHAR(100),
  scan_count_today       INTEGER        NOT NULL DEFAULT 0,
  scan_count_total       INTEGER        NOT NULL DEFAULT 0,
  email_verified         BOOLEAN        NOT NULL DEFAULT false,
  created_at             TIMESTAMPTZ    NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ    NOT NULL DEFAULT now(),
  last_login_at          TIMESTAMPTZ
);
CREATE INDEX idx_users_email ON users(email);

-- ── api_keys ──────────────────────────────────────────────────
CREATE TYPE key_status AS ENUM ('active','revoked','expired');

CREATE TABLE IF NOT EXISTS api_keys (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label        VARCHAR(100) NOT NULL,
  key_hash     VARCHAR(255) NOT NULL,
  key_prefix   VARCHAR(20)  NOT NULL,
  status       key_status   NOT NULL DEFAULT 'active',
  last_used_at TIMESTAMPTZ,
  use_count    INTEGER      NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  revoked_at   TIMESTAMPTZ
);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- ── scans ────────────────────────────────────────────────────
CREATE TYPE scan_engine AS ENUM ('local','claude_ai');

DO $$
BEGIN
  CREATE TYPE scan_source AS ENUM ('extension', 'web', 'mcp', 'api', 'cli', 'unknown');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS scans (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID         REFERENCES users(id) ON DELETE SET NULL,
  session_id      VARCHAR(64)  NOT NULL,
  platform        VARCHAR(50)  NOT NULL,
  language        VARCHAR(20)  NOT NULL,
  mode            VARCHAR(20)  NOT NULL DEFAULT 'quick',
  score           SMALLINT     NOT NULL CHECK (score BETWEEN 0 AND 100),
  grade           CHAR(1)      NOT NULL CHECK (grade IN ('A','B','C','D','F')),
  engine          scan_engine  NOT NULL,
  source          scan_source  NOT NULL DEFAULT 'unknown',
  critical_count  SMALLINT     NOT NULL DEFAULT 0,
  high_count      SMALLINT     NOT NULL DEFAULT 0,
  medium_count    SMALLINT     NOT NULL DEFAULT 0,
  lines_analysed  INTEGER,
  code_hash       CHAR(64)     NOT NULL,
  project_hash    VARCHAR(64),
  duration_ms     INTEGER,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
-- NOTE: code itself is NEVER stored in this table or anywhere in the database
CREATE INDEX idx_scans_user      ON scans(user_id);
CREATE INDEX idx_scans_created   ON scans(created_at DESC);
CREATE INDEX idx_scans_code_hash ON scans(code_hash);
CREATE INDEX IF NOT EXISTS idx_scans_project_hash ON scans(project_hash) WHERE project_hash IS NOT NULL;

-- ── project_usage ─────────────────────────────────────────────
-- One row per (project, actor): either authenticated user_id OR anonymous session_id.
-- Partial UNIQUE indexes make INSERT ... ON CONFLICT upserts race-safe for each actor kind.
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

-- ── mcp_installs ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mcp_installs (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  install_token_hash CHAR(64)     NOT NULL UNIQUE,
  locked_root_hash   CHAR(64)     NOT NULL,
  locked_root_hint   TEXT         NOT NULL,
  created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
  revoked_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mcp_installs_user_active
  ON mcp_installs(user_id, created_at DESC) WHERE revoked_at IS NULL;

-- ── scan_findings ─────────────────────────────────────────────
CREATE TYPE finding_severity AS ENUM ('critical','high','medium','low');

CREATE TABLE IF NOT EXISTS scan_findings (
  id              UUID              PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id         UUID              NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_id         VARCHAR(10)       NOT NULL,
  rule_name       VARCHAR(100)      NOT NULL,
  severity        finding_severity  NOT NULL,
  category        VARCHAR(50)       NOT NULL,
  line_number     SMALLINT,
  fix_description TEXT              NOT NULL
  -- NOTE: no 'snippet' column — code fragments are never stored
);
CREATE INDEX idx_findings_scan     ON scan_findings(scan_id);
CREATE INDEX idx_findings_severity ON scan_findings(severity);

-- ── checklist_results ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS checklist_results (
  id       UUID     PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id  UUID     NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  item_id  VARCHAR(5)  NOT NULL,
  item     TEXT        NOT NULL,
  critical BOOLEAN     NOT NULL DEFAULT false,
  pass     BOOLEAN     NOT NULL
);
CREATE INDEX idx_checklist_scan ON checklist_results(scan_id);

-- ── ip_passports ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_passports (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scan_id         UUID         NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
  project_name    VARCHAR(200) NOT NULL,
  fingerprint     CHAR(64)     NOT NULL,
  watermark_id    VARCHAR(32)  UNIQUE NOT NULL,
  language        VARCHAR(20)  NOT NULL,
  platform        VARCHAR(50)  NOT NULL,
  score_at_issue  SMALLINT     NOT NULL,
  issued_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
  pdf_url         VARCHAR(500)
);
CREATE INDEX idx_passports_user      ON ip_passports(user_id);
CREATE INDEX idx_passports_watermark ON ip_passports(watermark_id);

-- ── audit_logs ────────────────────────────────────────────────
CREATE TYPE audit_result AS ENUM ('success','failure','blocked');

CREATE TABLE IF NOT EXISTS audit_logs (
  id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID         REFERENCES users(id) ON DELETE SET NULL,
  action     VARCHAR(100) NOT NULL,
  resource   VARCHAR(100) NOT NULL DEFAULT '',
  ip_address INET,
  user_agent VARCHAR(500),
  result     audit_result NOT NULL DEFAULT 'success',
  created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_user    ON audit_logs(user_id);
CREATE INDEX idx_audit_action  ON audit_logs(action);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);

-- ── rate_limit_events ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limit_events (
  id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address INET         NOT NULL,
  endpoint   VARCHAR(100) NOT NULL,
  count      INTEGER      NOT NULL DEFAULT 1,
  window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_rle_ip_endpoint ON rate_limit_events(ip_address, endpoint);

-- ── waitlist_signups (marketing landing) ─────────────────────
CREATE TABLE IF NOT EXISTS waitlist_signups (
  id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  email      VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
  CONSTRAINT waitlist_signups_email_unique UNIQUE (email)
);
CREATE INDEX IF NOT EXISTS idx_waitlist_created ON waitlist_signups(created_at);

-- ── Row Level Security ────────────────────────────────────────
ALTER TABLE users           ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys        ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans           ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_findings   ENABLE ROW LEVEL SECURITY;
ALTER TABLE checklist_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_passports    ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs      ENABLE ROW LEVEL SECURITY;

-- Users can only see their own data
CREATE POLICY users_own_data      ON users          USING (id = current_setting('app.user_id', true)::uuid);
CREATE POLICY apikeys_own_data    ON api_keys       USING (user_id = current_setting('app.user_id', true)::uuid);
CREATE POLICY scans_own_data      ON scans          USING (user_id = current_setting('app.user_id', true)::uuid);
CREATE POLICY passports_own_data  ON ip_passports   USING (user_id = current_setting('app.user_id', true)::uuid);

-- ── Seed: plans reference ─────────────────────────────────────
-- (Plans are defined in code, not DB — but document here for reference)
-- free:  10 scans/month · local engine only · basic checklist
-- solo:  unlimited scans · Claude AI · IP Passport 1/month · $9/mo
-- pro:   unlimited · 5 projects · watermarking · investor PDF · $29/mo
-- admin: internal use only

-- ── Safe upgrades (rerunnable on live v1 databases) ───────────
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scan_source') THEN
    BEGIN
      ALTER TYPE scan_source ADD VALUE IF NOT EXISTS 'mcp';
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END;
  END IF;

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
