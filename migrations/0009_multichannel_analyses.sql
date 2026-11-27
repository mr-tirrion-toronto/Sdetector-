-- Store metadata and findings only. Never persist raw user-submitted SMS/email/message text.
CREATE TABLE IF NOT EXISTS public.channel_analyses (
  id UUID PRIMARY KEY,
  user_id UUID NULL REFERENCES public.app_users(id) ON DELETE SET NULL,
  channel TEXT NOT NULL CHECK (channel IN ('sms','email','phone','whatsapp','telegram','social','job','investment','qr','file')),
  risk_score SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  risk_level TEXT NOT NULL CHECK (risk_level IN ('low','guarded','high','critical')),
  signals JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_channel_analyses_user_created
  ON public.channel_analyses(user_id, created_at DESC);
