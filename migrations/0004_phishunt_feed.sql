-- Add the keyless CC0 Phishunt phishing-domain feed.
ALTER TABLE public.threat_feed_status
  DROP CONSTRAINT IF EXISTS threat_feed_status_source_check;
ALTER TABLE public.threat_feed_status
  ADD CONSTRAINT threat_feed_status_source_check
  CHECK (source IN ('urlhaus', 'phishtank', 'phishunt'));

ALTER TABLE public.threat_indicators
  DROP CONSTRAINT IF EXISTS threat_indicators_source_check;
ALTER TABLE public.threat_indicators
  ADD CONSTRAINT threat_indicators_source_check
  CHECK (source IN ('urlhaus', 'phishtank', 'phishunt'));
