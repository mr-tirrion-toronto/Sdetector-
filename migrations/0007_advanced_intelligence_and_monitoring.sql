-- Advanced evidence, scam-DNA fingerprints and user-managed change monitoring.
CREATE TABLE IF NOT EXISTS public.scan_intelligence (
  scan_id UUID PRIMARY KEY REFERENCES public.scans(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  dna_hash CHAR(64) NOT NULL,
  dna_family TEXT NOT NULL,
  snapshot_fingerprint CHAR(64),
  snapshot JSONB NOT NULL,
  scam_dna JSONB NOT NULL,
  brand_assessment JSONB NOT NULL,
  legitimacy_assessment JSONB NOT NULL,
  relationship_graph JSONB NOT NULL,
  change_summary JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_intelligence_hostname_created
  ON public.scan_intelligence (hostname, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_intelligence_dna_hash
  ON public.scan_intelligence (dna_hash, created_at DESC);

CREATE TABLE IF NOT EXISTS public.monitored_domains (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  interval_hours SMALLINT NOT NULL DEFAULT 24 CHECK (interval_hours BETWEEN 6 AND 168),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  next_check_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_checked_at TIMESTAMPTZ,
  last_scan_id UUID REFERENCES public.scans(id) ON DELETE SET NULL,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, hostname)
);
CREATE INDEX IF NOT EXISTS idx_monitored_domains_due
  ON public.monitored_domains (next_check_at, created_at) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_monitored_domains_user
  ON public.monitored_domains (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.monitor_snapshots (
  id UUID PRIMARY KEY,
  monitor_id UUID NOT NULL REFERENCES public.monitored_domains(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES public.scans(id) ON DELETE SET NULL,
  snapshot_fingerprint CHAR(64) NOT NULL,
  snapshot JSONB NOT NULL,
  change_summary JSONB NOT NULL,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_monitor_snapshots_monitor_checked
  ON public.monitor_snapshots (monitor_id, checked_at DESC);
