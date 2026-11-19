import { describe, expect, it } from "vitest";
import { hashPassword, passwordPolicyError } from "../src/auth";

describe("account password policy", () => {
  it("accepts a long, varied password", () => {
    expect(passwordPolicyError("N0t-a-Guessable-Phrase!")).toBeNull();
  });
  it("rejects passwords shorter than 12 characters", () => {
    expect(passwordPolicyError("short123!")).toContain("12");
  });
  it("rejects common sequences and repeated characters", () => {
    expect(passwordPolicyError("Password1234!")).toContain("common");
    expect(passwordPolicyError("AAAAaaaa1111!!!!")).toContain("repeating");
  });
  it("rejects a password containing the email name", () => {
    expect(passwordPolicyError("torontotirrion-2026!","torontotirrion@example.com")).toContain("email");
  });
});

describe("password hashing compatibility", () => {
  it("uses the expected PBKDF2-SHA256 format for stored account hashes", async () => {
    await expect(hashPassword("Valid-Test-Password-123!", "YWJjZGVmZ2hpamtsbW5vcA"))
      .resolves.toBe("5a96c7c93a20bd3e1596c2724aba94abbaeaeab38d4349e7143b1c6a8b746174");
  });
});
