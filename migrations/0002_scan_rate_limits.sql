-- Short-lived hashed client rate-limit buckets for the public scan endpoint.
-- The bucket key is a SHA-256 digest of the Cloudflare client IP and a 10-minute window.
CREATE TABLE IF NOT EXISTS public.scan_rate_limits (
  bucket_key TEXT PRIMARY KEY,
  request_count INTEGER NOT NULL CHECK (request_count > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_rate_limits_created_at
  ON public.scan_rate_limits (created_at);
