import { describe, expect, it } from "vitest";
import { buildIndependentEvidence } from "../src/independent-evidence";

describe("buildIndependentEvidence", () => {
  it("creates official registry, reputation and threat-history research links", () => {
    const result = buildIndependentEvidence({
      hostname: "example.com",
      pageTitle: "Get Paid to Chat with Foreigners",
      operatorNameCandidates: ["Example Chat Limited"],
      relatedDomains: ["other-example.com", "not a domain", "other-example.com"],
      campaignBrand: "chat campaign",
      campaignTotal: 4,
      certificateNames: ["example.com", "shared.example.net", "*.example.org"]
    });
    expect(result.status).toBe("manual_verification_required");
    expect(result.operatorNameCandidates).toEqual(["Example Chat Limited"]);
    expect(result.sources.map(source => source.id)).toContain("brela");
    expect(result.sources.map(source => source.id)).toContain("companies-house");
    expect(result.sources.map(source => source.id)).toContain("google-reputation");
    expect(result.sources.map(source => source.id)).toContain("google-safe-browsing");
    expect(result.sources.map(source => source.id)).toContain("urlscan");
    expect(result.sources.map(source => source.id)).toContain("ftc-task-scam-guidance");
    expect(result.sources.every(source => source.verification === "manual_review_required")).toBe(true);
    expect(result.sources.find(source => source.id === "companies-house")?.url).toContain(encodeURIComponent("Example Chat Limited"));
  });

  it("sanitizes related domains and labels technical relationships as leads only", () => {
    const result = buildIndependentEvidence({
      hostname: "example.com",
      relatedDomains: ["example.com", "evil.test/path", "linked.example.net"],
      certificateNames: ["*.example.net", "bad name", "example.com"]
    });
    expect(result.relationshipIntelligence.relatedDomains).toEqual(["linked.example.net"]);
    expect(result.relationshipIntelligence.certificateCoNames).toEqual(["example.net"]);
    expect(result.relationshipIntelligence.interpretation).toContain("do not prove common ownership");
  });

  it("does not claim that external checks have already been performed", () => {
    const result = buildIndependentEvidence({ hostname: "example.com" });
    expect(result.status).toBe("manual_verification_required");
    expect(result.limitations.join(" ")).toContain("not queried or verified");
    expect(result.sources.every(source => source.verification === "manual_review_required")).toBe(true);
  });
});
