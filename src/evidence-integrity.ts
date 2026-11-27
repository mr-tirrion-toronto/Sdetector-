export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export function canonicalJson(value: unknown): string {
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const record = value as Record<string, unknown>;
  return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonicalJson(record[key])).join(",") + "}";
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

export interface CustodyEventInput {
  evidenceId: string;
  sequenceNo: number;
  actorUserId: string;
  eventType: string;
  details: Record<string, unknown>;
  previousEventHash: string | null;
  createdAt: string;
}

export async function custodyEventHash(event: CustodyEventInput): Promise<string> {
  return sha256Hex(canonicalJson(event));
}

export async function verifyCustodyChain(
  events: Array<CustodyEventInput & { eventHash: string }>
): Promise<{ valid: boolean; checkedEvents: number; reason?: string }> {
  let previous: string | null = null;
  for (let index = 0; index < events.length; index++) {
    const event = events[index];
    if (event.sequenceNo !== index + 1) return { valid: false, checkedEvents: index, reason: "SEQUENCE_GAP" };
    if (event.previousEventHash !== previous) return { valid: false, checkedEvents: index, reason: "PREVIOUS_HASH_MISMATCH" };
    const { eventHash, ...payload } = event;
    if (await custodyEventHash(payload) !== eventHash) return { valid: false, checkedEvents: index + 1, reason: "EVENT_HASH_MISMATCH" };
    previous = eventHash;
  }
  return { valid: true, checkedEvents: events.length };
}
