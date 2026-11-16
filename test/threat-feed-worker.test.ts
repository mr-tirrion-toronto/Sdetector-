import { describe, expect, it } from "vitest";
import { canonicalUrl, csvObjects, parseCsv } from "../src/threat-feed-utils";
import { makePhishuntIndicators } from "../src/phishunt-feed";

describe("threat feed parsing", () => {
  it("parses quoted commas and escaped quote characters", () => {
    expect(parseCsv('id,url,target\n1,https://bad.example/a,"Bank, ""Example"""')).toEqual([
      ["id", "url", "target"],
      ["1", "https://bad.example/a", 'Bank, "Example"']
    ]);
  });

  it("preserves URLhaus comment-prefixed CSV header", () => {
    const rows = csvObjects('# URLhaus Database Dump\n# generated today\n# id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n"123","2026-11-16 12:00:00","https://bad.example/a","online","malware_download","tag","https://urlhaus.abuse.ch/url/123/","reporter"');
    expect(rows).toEqual([{
      id:"123",
      dateadded:"2026-11-16 12:00:00",
      url:"https://bad.example/a",
      url_status:"online",
      threat:"malware_download",
      tags:"tag",
      urlhaus_link:"https://urlhaus.abuse.ch/url/123/",
      reporter:"reporter"
    }]);
  });

  it("parses the PhishTank CSV header", () => {
    const rows = csvObjects('phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n123,https://bad.example/,https://phishtank.org/phish_detail.php?phish_id=123,2026-11-16T10:00:00Z,yes,2026-11-16T10:01:00Z,yes,Example Bank');
    expect(rows[0].phish_id).toBe("123");
    expect(rows[0].verified).toBe("yes");
  });

  it("canonicalizes host case and strips credentials and fragments", () => {
    expect(canonicalUrl("https://user:pass@EXAMPLE.com/path#frag")).toEqual({
      value:"https://example.com/path",
      hostname:"example.com"
    });
  });

  it("imports normalized Phishunt hostnames and deduplicates URLs", async () => {
    const indicators = await makePhishuntIndicators("https://Phish.Example/login\nhttp://phish.example/verify\nnot a url\nlocalhost\n");
    expect(indicators).toHaveLength(1);
    expect(indicators[0].hostname).toBe("phish.example");
    expect(indicators[0].threat_type).toBe("phishing_domain");
    expect(indicators[0].indicator_hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("rejects non-web schemes", () => {
    expect(canonicalUrl("file:///etc/passwd")).toBeNull();
  });
});
