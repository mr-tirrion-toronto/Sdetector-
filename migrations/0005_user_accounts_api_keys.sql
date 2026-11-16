-- User accounts, private scan ownership and revocable API credentials
CREATE TABLE IF NOT EXISTS public.app_users (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_users_email_lower ON public.app_users (LOWER(email));
CREATE TABLE IF NOT EXISTS public.user_sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_expiry ON public.user_sessions (user_id, expires_at DESC);
CREATE TABLE IF NOT EXISTS public.user_api_keys (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_user_created ON public.user_api_keys (user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS public.auth_rate_limits (
  bucket_key CHAR(64) NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('register', 'login')),
  request_count INTEGER NOT NULL DEFAULT 0,
  window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (bucket_key, action)
);
CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_window ON public.auth_rate_limits (window_started_at);
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES public.app_users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_scans_user_created ON public.scans (user_id, created_at DESC);
