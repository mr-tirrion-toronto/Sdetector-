import { describe, expect, it } from "vitest";
import { passwordPolicyError } from "../src/auth";

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
