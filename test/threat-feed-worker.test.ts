import { describe, expect, it } from "vitest";
import { canonicalUrl, csvObjects, parseCsv } from "../feed-worker/index";

describe("threat feed parsing", () => {
  it("parses quoted commas and escaped quote characters", () => {
    expect(parseCsv('id,url,target\\n1,https://bad.example/a,"Bank, ""Example"""')).toEqual([
      ["id", "url", "target"],
      ["1", "https://bad.example/a", 'Bank, "Example"']
    ]);
  });

  it("ignores comment lines before the header", () => {
    const rows = csvObjects('# URLhaus feed\\n# generated today\\nid,url,url_status\\n1,https://bad.example/,online');
    expect(rows).toEqual([{id:"1",url:"https://bad.example/",url_status:"online"}]);
  });

  it("canonicalizes host case and strips credentials and fragments", () => {
    expect(canonicalUrl("https://user:pass@EXAMPLE.com/path#frag")).toEqual({
      value:"https://example.com/path",
      hostname:"example.com"
    });
  });

  it("rejects non-web schemes", () => {
    expect(canonicalUrl("file:///etc/passwd")).toBeNull();
  });
});
