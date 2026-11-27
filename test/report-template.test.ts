import { readFileSync } from "node:fs";
import { Script } from "node:vm";
import { describe, expect, it } from "vitest";

describe("report page template", () => {
  it("contains a syntactically valid inline report renderer", () => {
    const html = readFileSync(new URL("../public/report.html", import.meta.url), "utf8");
    const match = html.match(/<script>\s*([\s\S]*?)<\/script>/i);
    expect(match?.[1]).toBeTruthy();
    expect(() => new Script(match![1])).not.toThrow();
  });

  it("shows a helpful error when opened without a scan report", () => {
    const html = readFileSync(new URL("../public/report.html", import.meta.url), "utf8");
    expect(html).toContain("No report data was found. Return to the scanner and generate a new report.");
    expect(html).toContain("Report unavailable");
  });
});
