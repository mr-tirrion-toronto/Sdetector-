import { describe, expect, it } from "vitest";
import { hashPassword, newSalt, randomToken, sha256 } from "../src/auth";

describe("account credential helpers", () => {
  it("derives a repeatable salted password hash", async () => {
    const salt = newSalt();
    const first = await hashPassword("correct horse battery staple", salt);
    const second = await hashPassword("correct horse battery staple", salt);
    const different = await hashPassword("different password", salt);
    expect(first).toBe(second);
    expect(first).not.toBe(different);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
  });
  it("creates high-entropy URL-safe session tokens and SHA-256 hashes", async () => {
    const token = randomToken(32);
    expect(token).toMatch(/^[A-Za-z0-9_-]{40,50}$/);
    expect(await sha256(token)).toMatch(/^[a-f0-9]{64}$/);
  });
});
