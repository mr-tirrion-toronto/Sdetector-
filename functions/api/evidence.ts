import { neon } from "@neondatabase/serverless";
import { getAuthenticatedUser, isSameOriginMutation, json } from "../../src/auth";
import { canonicalJson, custodyEventHash, verifyCustodyChain } from "../../src/evidence-integrity";

interface Env { DATABASE_URL?: string }
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
type EventType = "record_created" | "pdf_export_initiated" | "integrity_verified";

async function appendEvent(sql: any, evidenceId: string, actorUserId: string, eventType: EventType, details: Record<string, unknown>) {
  const previousRows = await sql`SELECT sequence_no, event_hash FROM evidence_custody_events
    WHERE evidence_id = ${evidenceId} ORDER BY sequence_no DESC LIMIT 1`;
  const previous = (previousRows as Array<{sequence_no:number|string;event_hash:string}>)[0];
  const sequenceNo = Number(previous?.sequence_no ?? 0) + 1;
  const previousEventHash = previous?.event_hash?.trim() || null;
  const timeRows = await sql`SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at`;
  const createdAt = String((timeRows as Array<{created_at:string}>)[0]?.created_at || new Date().toISOString());
  const event = { evidenceId, sequenceNo, actorUserId, eventType, details, previousEventHash, createdAt };
  const eventHash = await custodyEventHash(event);
  await sql`INSERT INTO evidence_custody_events
    (id,evidence_id,sequence_no,actor_user_id,event_type,details,previous_event_hash,event_hash,created_at)
    VALUES (${crypto.randomUUID()},${evidenceId},${sequenceNo},${actorUserId},${eventType},
      ${JSON.stringify(details)}::jsonb,${previousEventHash},${eventHash},${createdAt}::timestamptz)`;
  return { sequenceNo, eventHash, createdAt };
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  if (!isSameOriginMutation(request)) return json({ error: "Cross-origin request rejected." }, 403);
  if (!request.headers.get("content-type")?.toLowerCase().includes("application/json")) return json({ error: "Content-Type must be application/json." }, 415);
  const length = Number(request.headers.get("content-length") ?? "0");
  if (length > 8000) return json({ error: "Request body is too large." }, 413);
  let body: any;
  try { const raw = await request.text(); if (raw.length > 8000) return json({ error: "Request body is too large." }, 413); body = JSON.parse(raw); }
  catch { return json({ error: "A valid JSON body is required." }, 400); }
  if (!env.DATABASE_URL) return json({ error: "Evidence preservation is temporarily unavailable." }, 503);
  const sql = neon(env.DATABASE_URL);
  let user;
  try { user = await getAuthenticatedUser(sql, request); }
  catch { return json({ error: "Authentication service is temporarily unavailable." }, 503); }
  if (!user) return json({ error: "Sign in to create or manage a preserved evidence record." }, 401);

  try {
    if (typeof body?.scanId === "string" && UUID.test(body.scanId)) {
      const scanRows = await sql`SELECT id::text, input_url, hostname, risk_score, risk_level, created_at
        FROM scans WHERE id = ${body.scanId} AND user_id = ${user.id} LIMIT 1`;
      const scan = (scanRows as Array<Record<string, any>>)[0];
      if (!scan) return json({ error: "The scan was not found in this account. Guest scans cannot be placed in the account evidence vault." }, 404);
      const [findingRows, intelligenceRows] = await Promise.all([
        sql`SELECT id::text, code, title, severity, points, evidence, recommendation
          FROM scan_findings WHERE scan_id = ${scan.id} ORDER BY id ASC`,
        sql`SELECT dna_hash, dna_family, snapshot_fingerprint, snapshot, scam_dna,
            brand_assessment, legitimacy_assessment, relationship_graph, change_summary, created_at
          FROM scan_intelligence WHERE scan_id = ${scan.id} LIMIT 1`
      ]);
      const intelligence = (intelligenceRows as Array<Record<string, any>>)[0] ?? null;
      const manifestId = crypto.randomUUID();
      const manifest = {
        manifestVersion: 1,
        evidenceId: manifestId,
        scanId: scan.id,
        system: { name: "Scam Detector", recordType: "Automated website security observation", source: "Server-persisted scan records" },
        collection: {
          recordedAt: new Date().toISOString(),
          originalScanTimestamp: scan.created_at,
          method: "Automated remote URL, threat-intelligence, domain and live-inspection checks as reflected in retained scan records",
          target: { hostname: scan.hostname, submittedUrl: scan.input_url, urlHandling: "Credentials, fragment and configured sensitive query parameters are redacted before persistence." }
        },
        assessment: { score: Number(scan.risk_score), riskLevel: scan.risk_level },
        findings: findingRows,
        retainedIntelligence: intelligence ? {
          dnaHash: intelligence.dna_hash,
          dnaFamily: intelligence.dna_family,
          snapshotFingerprint: intelligence.snapshot_fingerprint,
          snapshot: intelligence.snapshot,
          scamDna: intelligence.scam_dna,
          brandAssessment: intelligence.brand_assessment,
          legitimacyAssessment: intelligence.legitimacy_assessment,
          relationshipGraph: intelligence.relationship_graph,
          changeSummary: intelligence.change_summary,
          recordedAt: intelligence.created_at
        } : null,
        evidenceScope: {
          included: ["persisted scan metadata", "persisted findings", "retained intelligence snapshot and assessments when available"],
          excluded: ["raw HTTP traffic", "complete third-party provider responses not retained by the scanner", "browser state", "original website files", "PDF bytes", "independent device or network acquisition"],
          note: "This manifest preserves only the server records listed above. It is not a full forensic image or a complete copy of every transient live check."
        }
      };
      const { sha256Hex } = await import("../../src/evidence-integrity");
      const manifestSha256 = await sha256Hex(canonicalJson(manifest));
      await sql`INSERT INTO evidence_records
        (id,scan_id,user_id,manifest_version,manifest,manifest_sha256)
        VALUES (${manifestId},${scan.id},${user.id},1,${JSON.stringify(manifest)}::jsonb,${manifestSha256})
        ON CONFLICT (scan_id,user_id) DO NOTHING`;
      const recordRows = await sql`SELECT id::text, manifest, manifest_sha256, created_at
        FROM evidence_records WHERE scan_id = ${scan.id} AND user_id = ${user.id} LIMIT 1`;
      const record = (recordRows as Array<Record<string, any>>)[0];
      if (!record) return json({ error: "Could not persist the evidence manifest." }, 503);
      const eventRows = await sql`SELECT sequence_no FROM evidence_custody_events WHERE evidence_id = ${record.id} LIMIT 1`;
      if (!eventRows.length) {
        try {
          await appendEvent(sql, record.id, user.id, "record_created", {
            manifestSha256: String(record.manifest_sha256).trim(),
            manifestVersion: 1,
            source: "server-side scan persistence"
          });
        } catch (error) {
          console.error("EVIDENCE_INITIAL_CUSTODY_EVENT_FAILED", error instanceof Error ? error.name : "UnknownError");
          return json({ error: "Evidence record exists, but its first custody event could not be recorded. Retry the request." }, 503);
        }
      }
      return json({
        evidenceId: record.id,
        scanId: scan.id,
        manifestSha256: String(record.manifest_sha256).trim(),
        createdAt: record.created_at,
        status: "preserved",
        reused: record.id !== manifestId,
        note: "Server-side manifest of retained scan records. It is not a signed forensic acquisition or trusted timestamp."
      });
    }

    if (typeof body?.evidenceId !== "string" || !UUID.test(body.evidenceId)) return json({ error: "Provide a valid scanId or evidenceId." }, 400);
    const eventType = body?.eventType as EventType;
    if (!["pdf_export_initiated", "integrity_verified"].includes(eventType)) return json({ error: "Unsupported custody event." }, 400);
    const records = await sql`SELECT id, manifest, manifest_sha256 FROM evidence_records
      WHERE id = ${body.evidenceId} AND user_id = ${user.id} LIMIT 1`;
    const record = (records as Array<Record<string, any>>)[0];
    if (!record) return json({ error: "Evidence record not found in this account." }, 404);
    if (eventType === "integrity_verified") {
      const { sha256Hex } = await import("../../src/evidence-integrity");
      const digest = await sha256Hex(canonicalJson(record.manifest));
      if (digest !== String(record.manifest_sha256).trim()) return json({ error: "Manifest integrity check failed; verification event was not recorded." }, 409);
      const eventRows = await sql`SELECT evidence_id::text, sequence_no, actor_user_id::text, event_type, details,
          previous_event_hash, event_hash, created_at
        FROM evidence_custody_events WHERE evidence_id = ${body.evidenceId} ORDER BY sequence_no ASC`;
      const events = (eventRows as Array<Record<string, any>>).map(row => ({
        evidenceId: row.evidence_id, sequenceNo: Number(row.sequence_no), actorUserId: row.actor_user_id,
        eventType: row.event_type, details: row.details ?? {}, previousEventHash: row.previous_event_hash?.trim() || null,
        eventHash: String(row.event_hash).trim(), createdAt: new Date(row.created_at).toISOString()
      }));
      const chain = await verifyCustodyChain(events);
      if (!chain.valid) return json({ error: "Custody chain verification failed.", integrity: chain }, 409);
    }
    const details = eventType === "pdf_export_initiated"
      ? { format: "application/pdf", source: "report-print-control", savedFileConfirmed: false, note: "The browser print dialog was initiated; the server cannot verify whether the user saved a PDF." }
      : { manifestSha256: String(record.manifest_sha256).trim(), verifiedBy: "server-side SHA-256 and custody-chain verification" };
    const event = await appendEvent(sql, body.evidenceId, user.id, eventType, details);
    return json({ status: "recorded", event });
  } catch (error) {
    console.error("EVIDENCE_PRESERVATION_FAILED", error instanceof Error ? error.name : "UnknownError");
    return json({ error: "Evidence preservation could not be completed. Please retry." }, 503);
  }
};

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  if (!env.DATABASE_URL) return json({ error: "Evidence preservation is temporarily unavailable." }, 503);
  const id = new URL(request.url).searchParams.get("id") ?? "";
  if (!UUID.test(id)) return json({ error: "Provide a valid evidence record id." }, 400);
  const sql = neon(env.DATABASE_URL);
  try {
    const user = await getAuthenticatedUser(sql, request);
    if (!user) return json({ error: "Sign in to view this evidence record." }, 401);
    const rows = await sql`SELECT id::text, scan_id::text, manifest, manifest_sha256, created_at
      FROM evidence_records WHERE id = ${id} AND user_id = ${user.id} LIMIT 1`;
    const record = (rows as Array<Record<string, any>>)[0];
    if (!record) return json({ error: "Evidence record not found in this account." }, 404);
    const { sha256Hex } = await import("../../src/evidence-integrity");
    const digest = await sha256Hex(canonicalJson(record.manifest));
    const eventRows = await sql`SELECT evidence_id::text, sequence_no, actor_user_id::text, event_type, details,
        previous_event_hash, event_hash, created_at
      FROM evidence_custody_events WHERE evidence_id = ${id} ORDER BY sequence_no ASC`;
    const events = (eventRows as Array<Record<string, any>>).map(row => ({
      evidenceId: row.evidence_id, sequenceNo: Number(row.sequence_no), actorUserId: row.actor_user_id,
      eventType: row.event_type, details: row.details ?? {}, previousEventHash: row.previous_event_hash?.trim() || null,
      eventHash: String(row.event_hash).trim(), createdAt: new Date(row.created_at).toISOString()
    }));
    const chain = await verifyCustodyChain(events);
    return json({
      evidenceId: record.id,
      scanId: record.scan_id,
      manifest: record.manifest,
      manifestSha256: String(record.manifest_sha256).trim(),
      createdAt: record.created_at,
      integrity: { manifestValid: digest === String(record.manifest_sha256).trim(), custodyChain: chain },
      custodyEvents: events.map(({ eventHash, ...event }) => ({ ...event, eventHash }))
    });
  } catch (error) {
    console.error("EVIDENCE_RECORD_READ_FAILED", error instanceof Error ? error.name : "UnknownError");
    return json({ error: "Could not read the evidence record." }, 503);
  }
};
