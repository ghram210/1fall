-- ============================================================
-- Vulnerability Manager - Supabase Migration
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- ============================================================

-- 1. Ensure scan_results has all needed columns
-- (The table likely already exists — we only add what's missing)

ALTER TABLE scan_results
  ADD COLUMN IF NOT EXISTS raw_output TEXT,
  ADD COLUMN IF NOT EXISTS error_message TEXT,
  ADD COLUMN IF NOT EXISTS agent_id TEXT;

-- Update status default to 'pending' (for new queue-based workflow)
ALTER TABLE scan_results
  ALTER COLUMN status SET DEFAULT 'pending';

-- 2. Create scan_findings table
-- Stores individual vulnerability findings per scan
CREATE TABLE IF NOT EXISTS scan_findings (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_result_id UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
  title          TEXT NOT NULL,
  severity       TEXT NOT NULL DEFAULT 'info',  -- critical | high | medium | low | info
  description    TEXT,
  url            TEXT,
  port           INTEGER,
  service        TEXT,
  tool           TEXT NOT NULL,
  details        TEXT,
  discovered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast lookup by scan
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_result_id
  ON scan_findings (scan_result_id);

-- 3. Enable Row Level Security (RLS)
ALTER TABLE scan_findings ENABLE ROW LEVEL SECURITY;

-- Allow authenticated users to read all findings
CREATE POLICY IF NOT EXISTS "Authenticated users can read findings"
  ON scan_findings FOR SELECT
  TO authenticated
  USING (true);

-- Allow service_role (Kali agent) to insert findings
CREATE POLICY IF NOT EXISTS "Service role can insert findings"
  ON scan_findings FOR INSERT
  TO service_role
  WITH CHECK (true);

-- Allow service_role to update scan_results (to change status)
CREATE POLICY IF NOT EXISTS "Service role can update scan_results"
  ON scan_results FOR UPDATE
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Allow service_role to read scan_results
CREATE POLICY IF NOT EXISTS "Service role can read scan_results"
  ON scan_results FOR SELECT
  TO service_role
  USING (true);

-- 4. Grant permissions to anon key for the agent
-- (If you prefer using the anon key instead of service_role key)
-- Uncomment below if needed:
--
-- CREATE POLICY "Anon can read pending scans" ON scan_results FOR SELECT TO anon USING (true);
-- CREATE POLICY "Anon can update scan_results" ON scan_results FOR UPDATE TO anon USING (true);
-- CREATE POLICY "Anon can insert findings" ON scan_findings FOR INSERT TO anon WITH CHECK (true);
-- CREATE POLICY "Anon can read findings" ON scan_findings FOR SELECT TO anon USING (true);

-- Done!
-- After running this migration, copy your Supabase service_role key
-- and SUPABASE_URL into the Kali agent configuration.
