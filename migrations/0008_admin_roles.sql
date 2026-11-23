-- Explicit roles for the private Scam Detector administrator console.
-- Existing accounts remain ordinary users. Promote an owner account manually
-- only after this migration has been applied and the identity is verified.
ALTER TABLE public.app_users
  ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';

ALTER TABLE public.app_users
  DROP CONSTRAINT IF EXISTS app_users_role_check;

ALTER TABLE public.app_users
  ADD CONSTRAINT app_users_role_check
  CHECK (role IN ('user', 'admin'));

CREATE INDEX IF NOT EXISTS idx_app_users_role_created
  ON public.app_users (role, created_at DESC);
