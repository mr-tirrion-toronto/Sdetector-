CREATE TABLE IF NOT EXISTS scans (
 id UUID PRIMARY KEY,input_url TEXT NOT NULL,normalized_url TEXT NOT NULL,hostname TEXT NOT NULL,
 risk_score SMALLINT NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
 risk_level TEXT NOT NULL CHECK(risk_level IN ('unknown','low','guarded','high','critical')),
 assessment_status TEXT NOT NULL DEFAULT 'preliminary' CHECK(assessment_status IN ('insufficient_evidence','preliminary','verified_threat')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scans_hostname_created_at ON scans(hostname,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE TABLE IF NOT EXISTS scan_findings(
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
 code TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high')),
 points SMALLINT NOT NULL CHECK(points>=0),evidence TEXT NOT NULL,recommendation TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON scan_findings(scan_id);