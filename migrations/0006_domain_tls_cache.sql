CREATE TABLE IF NOT EXISTS public.domain_tls_cache (
  hostname TEXT PRIMARY KEY,
  tls_data JSONB NOT NULL,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_domain_tls_cache_expiry ON public.domain_tls_cache (expires_at);
