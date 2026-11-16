-- Threat intelligence feed metadata and hash-only indicators.
-- Raw malicious URLs are deliberately not persisted in this table.
CREATE TABLE IF NOT EXISTS public.threat_feed_status (
  source TEXT PRIMARY KEY CHECK (source IN ('urlhaus', 'phishtank')),
  status TEXT NOT NULL CHECK (status IN ('ok', 'error', 'not_configured')),
  last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_success_at TIMESTAMPTZ,
  etag TEXT,
  item_count INTEGER NOT NULL DEFAULT 0 CHECK (item_count >= 0),
  error_code TEXT
);

CREATE TABLE IF NOT EXISTS public.threat_indicators (
  source TEXT NOT NULL CHECK (source IN ('urlhaus', 'phishtank')),
  indicator_hash CHAR(64) NOT NULL,
  source_id TEXT,
  hostname TEXT NOT NULL,
  threat_type TEXT NOT NULL,
  target TEXT,
  source_updated_at TIMESTAMPTZ,
  imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (source, indicator_hash)
);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_hash_expiry
  ON public.threat_indicators (indicator_hash, expires_at);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_expiry
  ON public.threat_indicators (expires_at);

CREATE INDEX IF NOT EXISTS idx_threat_feed_status_freshness
  ON public.threat_feed_status (last_success_at DESC);
