import { describe, expect, it } from "vitest";
import { canonicalJson, custodyEventHash, verifyCustodyChain } from "../src/evidence-integrity";

describe("evidence integrity", () => {
  it("canonicalizes object keys deterministically", () => {
    expect(canonicalJson({ b: 2, a: 1 })).toBe(canonicalJson({ a: 1, b: 2 }));
  });
  it("detects changes to a custody event", async () => {
    const first = { evidenceId: "e1", sequenceNo: 1, actorUserId: "u1", eventType: "record_created", details: {}, previousEventHash: null, createdAt: "2026-11-27T00:00:00.000Z" };
    const eventHash = await custodyEventHash(first);
    expect(await verifyCustodyChain([{ ...first, eventHash }])).toEqual({ valid: true, checkedEvents: 1 });
    expect((await verifyCustodyChain([{ ...first, eventType: "pdf_exported", eventHash }])).valid).toBe(false);
  });
  it("detects a broken previous-hash link", async () => {
    const first = { evidenceId: "e1", sequenceNo: 1, actorUserId: "u1", eventType: "record_created", details: {}, previousEventHash: null, createdAt: "2026-11-27T00:00:00.000Z" };
    const firstHash = await custodyEventHash(first);
    const second = { evidenceId: "e1", sequenceNo: 2, actorUserId: "u1", eventType: "pdf_exported", details: {}, previousEventHash: "wrong", createdAt: "2026-11-27T00:01:00.000Z" };
    const secondHash = await custodyEventHash(second);
    const result = await verifyCustodyChain([{ ...first, eventHash: firstHash }, { ...second, eventHash: secondHash }]);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("PREVIOUS_HASH_MISMATCH");
  });
});
