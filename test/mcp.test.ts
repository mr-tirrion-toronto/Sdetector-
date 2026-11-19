import { describe, expect, it } from "vitest";
import { onRequestGet, onRequestPost } from "../functions/mcp";

function context(message: unknown, env: Record<string, unknown> = {}) {
  return {
    request: new Request("https://scam-detector.test/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(message)
    }),
    env
  };
}

describe("Scam Detector MCP endpoint", () => {
  it("negotiates a supported protocol version", async () => {
    const response = await (onRequestPost as any)(context({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1.0" } }
    }));
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(body.result.protocolVersion).toBe("2025-06-18");
    expect(body.result.capabilities.tools.listChanged).toBe(false);
    expect(body.result.serverInfo.name).toBe("scam-detector");
  });

  it("publishes the website investigation, AI assistant and health tools", async () => {
    const response = await (onRequestPost as any)(context({
      jsonrpc: "2.0",
      id: "tools",
      method: "tools/list"
    }));
    const body = await response.json();
    expect(body.result.tools.map((tool: { name: string }) => tool.name)).toEqual([
      "investigate_website",
      "ask_scam_detector_ai",
      "get_scanner_health"
    ]);
  });

  it("acknowledges initialized notifications without a JSON body", async () => {
    const response = await (onRequestPost as any)(context({
      jsonrpc: "2.0",
      method: "notifications/initialized"
    }));
    expect(response.status).toBe(202);
    expect(await response.text()).toBe("");
  });

  it("returns a JSON-RPC method-not-found error for unsupported methods", async () => {
    const response = await (onRequestPost as any)(context({
      jsonrpc: "2.0",
      id: 9,
      method: "resources/list"
    }));
    const body = await response.json();
    expect(body.error.code).toBe(-32601);
  });

  it("returns 405 for GET because this stateless endpoint does not offer SSE", async () => {
    const response = await (onRequestGet as any)({ request: new Request("https://scam-detector.test/mcp"), env: {} });
    expect(response.status).toBe(405);
  });
});
