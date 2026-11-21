-- Privacy-conscious aggregate website analytics.
CREATE TABLE IF NOT EXISTS public.site_events (id UUID PRIMARY KEY,event_type TEXT NOT NULL CHECK (event_type IN ('page_view','scan_completed','assistant_question')),country_code CHAR(2),page_path TEXT NOT NULL,referrer_host TEXT,device_type TEXT NOT NULL DEFAULT 'unknown' CHECK (device_type IN ('mobile','desktop','tablet','unknown')),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_site_events_created_at ON public.site_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_site_events_country_created ON public.site_events (country_code, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_site_events_type_created ON public.site_events (event_type, created_at DESC);
