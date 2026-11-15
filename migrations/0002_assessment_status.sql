ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_risk_level_check;
ALTER TABLE scans ADD CONSTRAINT scans_risk_level_check CHECK (risk_level IN ('unknown','low','guarded','high','critical'));
ALTER TABLE scans ADD COLUMN IF NOT EXISTS assessment_status TEXT NOT NULL DEFAULT 'preliminary';
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_assessment_status_check;
ALTER TABLE scans ADD CONSTRAINT scans_assessment_status_check CHECK (assessment_status IN ('insufficient_evidence','preliminary','verified_threat'));
UPDATE scans SET risk_level='unknown',assessment_status='insufficient_evidence' WHERE risk_score=0 AND risk_level='low';