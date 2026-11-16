import { describe, expect, it } from "vitest";
import { analyzeBusinessClaims } from "../src/business-claims";

describe("analyzeBusinessClaims", () => {

  it("reports operator identity disclosure without claiming official verification", () => {
    const result = analyzeBusinessClaims("Example platform. support@example.com. Example Limited.", '<a href="/terms">Terms of Service</a><a href="/privacy">Privacy Policy</a>');
    expect(result.operatorDisclosure.legalEntityDetected).toBe(true);
    expect(result.operatorDisclosure.contactDetailsDetected).toBe(true);
    expect(result.operatorDisclosure.termsLinkDetected).toBe(true);
    expect(result.operatorDisclosure.privacyLinkDetected).toBe(true);
    expect(result.operatorVerification).toBe("not_independently_verified");
  });

  it("flags incomplete operator disclosures as an information signal, not proof of fraud", () => {
    const result = analyzeBusinessClaims("Earn money chatting with foreigners.");
    expect(result.signals).toContain("operator_identity_disclosure_incomplete");
    expect(result.findings.find(item => item.code === "BUSINESS_OPERATOR_DETAILS_INCOMPLETE")?.points).toBe(0);
  });

  it("recognizes paid-chat claims without calling them proof of fraud", () => {
    const result = analyzeBusinessClaims("Get paid to chat with foreigners and earn money for every message.");
    expect(result.model).toBe("paid_chat_or_task_claim");
    expect(result.signals).toContain("paid_chat_business_claim");
    expect(result.findings.find(item => item.code === "BUSINESS_PAID_CHAT_CLAIM")?.points).toBe(0);
    expect(result.payoutVerification).toBe("not_verified_from_public_page");
  });

  it("flags pay-to-withdraw language as a strong warning", () => {
    const result = analyzeBusinessClaims("Pay a withdrawal fee to unlock your payout.");
    expect(result.signals).toContain("payment_required_to_withdraw_claim");
    expect(result.findings.some(item => item.code === "BUSINESS_PAY_TO_WITHDRAW" && item.points >= 30)).toBe(true);
  });

  it("detects activation fees and recharge-to-earn claims", () => {
    const result = analyzeBusinessClaims("Pay an activation fee to start earning. Recharge to unlock tasks and commissions.");
    expect(result.signals).toContain("upfront_payment_for_work_claim");
    expect(result.signals).toContain("recharge_to_earn_model");
  });

  it("treats testimonials and payout counters as unverified claims", () => {
    const result = analyzeBusinessClaims("80,000 members. $1.2M paid out. Instant payouts and success stories.");
    expect(result.signals).toContain("self_published_payout_or_social_proof_claim");
    expect(result.findings.find(item => item.code === "BUSINESS_UNVERIFIED_PAYOUT_CLAIM")?.points).toBe(0);
  });

  it("does not flag an ordinary language exchange page as an earning scheme", () => {
    const result = analyzeBusinessClaims("Join a free language exchange and practise Swahili with international learners.");
    expect(result.model).toBe("not_detected");
    expect(result.findings).toHaveLength(0);
  });
});
