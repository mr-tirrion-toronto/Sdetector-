import { neon } from "@neondatabase/serverless";
import { getAuthenticatedUser } from "../src/auth";
import { onRequestPost as scanPost } from "./api/scan";
import { onRequestPost as assistantPost } from "./api/ai/assistant";
import { onRequestGet as healthGet } from "./api/health";

interface Env {
  DATABASE_URL?: string;
  OPENAI_API_KEY?: string;
  OPENAI_MODEL?: string;
}

const PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"];
const MAX_BODY = 12_288;
const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, GET, DELETE, OPTIONS",
  "access-control-allow-headers": "Authorization, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id",
  "access-control-expose-headers": "MCP-Protocol-Version, MCP-Session-Id",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff"
};

const TOOLS = [
  {
    name: "investigate_website",
    title: "Investigate a website",
    description: "Run Scam Detector's URL and domain investigation. Returns structured risk indicators, findings, technical evidence, source availability and limitations. This is not a guarantee of safety. Submit only public HTTP/HTTPS URLs; never include credentials, OTPs or private tokens.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["url"],
      properties: {
        url: { type: "string", minLength: 1, maxLength: 2048, description: "Public HTTP or HTTPS URL to investigate." }
      }
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }
  },
  {
    name: "ask_scam_detector_ai",
    title: "Ask Scam Detector AI",
    description: "Ask evidence-grounded follow-up questions about a saved scan owned by your authenticated account, or ask general questions about Scam Detector. First call investigate_website and pass its scanId as scan_id for site-specific questions. The assistant never certifies a website as safe.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["question"],
      properties: {
        question: { type: "string", minLength: 1, maxLength: 3000, description: "Question about a scan or Scam Detector." },
        scan_id: { type: "string", format: "uuid", description: "Optional scanId returned by investigate_website." }
      }
    },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
  },
  {
    name: "get_scanner_health",
    title: "Check scanner health",
    description: "Check whether Scam Detector's API and Neon database are available.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
  }
];

function response(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: CORS_HEADERS });
}

function rpc(id: string | number | null, result: unknown): Response {
  return response({ jsonrpc: "2.0", id, result });
}

function rpcError(id: string | number | null, code: number, message: string): Response {
  return response({ jsonrpc: "2.0", id, error: { code, message } }, 200);
}

function toolResult(value: unknown, isError = false): Response {
  const serialized = JSON.stringify(value);
  return response({
    jsonrpc: "2.0",
    id: null,
    result: {
      content: [{ type: "text", text: serialized.length > 18_000 ? serialized.slice(0, 18_000) + "… [truncated]" : serialized }],
      structuredContent: value,
      isError
    }
  });
}

async function invokeHandler(
  handler: (context: any) => Promise<Response>,
  request: Request,
  env: Env
): Promise<Response> {
  return handler({ request, env } as any);
}

async function callTool(name: string, args: Record<string, unknown>, request: Request, env: Env): Promise<Response> {
  if (name === "get_scanner_health") {
    const healthRequest = new Request(new URL("/api/health", request.url), { method: "GET", headers: request.headers });
    const healthResponse = await invokeHandler(healthGet as any, healthRequest, env);
    const data = await healthResponse.json().catch(() => ({ error: "Health endpoint returned an unreadable response." }));
    return toolResult(data, !healthResponse.ok);
  }

  if (!env.DATABASE_URL) {
    return toolResult({ error: "Scam Detector account authentication is unavailable." }, true);
  }
  let user: Awaited<ReturnType<typeof getAuthenticatedUser>>;
  try {
    user = await getAuthenticatedUser(neon(env.DATABASE_URL), request);
  } catch (error) {
    console.error("MCP_AUTH_LOOKUP_FAILED", error instanceof Error ? error.name : "UnknownError");
    return toolResult({ error: "Could not verify the Scam Detector account API key." }, true);
  }
  if (!user) return toolResult({ error: "Connect with a valid Scam Detector account API key (sd_live_...). The OpenAI Platform key is not used for MCP client authentication." }, true);

  if (name === "investigate_website") {
    if (typeof args.url !== "string" || !args.url.trim() || args.url.length > 2048) {
      return toolResult({ error: "Provide a public HTTP or HTTPS URL between 1 and 2048 characters." }, true);
    }
    const scanRequest = new Request(new URL("/api/scan", request.url), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": request.headers.get("authorization") ?? "",
        ...(request.headers.get("cf-connecting-ip") ? { "cf-connecting-ip": request.headers.get("cf-connecting-ip")! } : {})
      },
      body: JSON.stringify({ url: args.url })
    });
    const scanResponse = await invokeHandler(scanPost as any, scanRequest, env);
    const data = await scanResponse.json().catch(() => ({ error: "Scanner returned an unreadable response." }));
    return toolResult(data, !scanResponse.ok);
  }

  if (name === "ask_scam_detector_ai") {
    if (typeof args.question !== "string" || !args.question.trim() || args.question.length > 3000) {
      return toolResult({ error: "Provide a question between 1 and 3000 characters." }, true);
    }
    if (args.scan_id !== undefined &&
        (typeof args.scan_id !== "string" || !/^[0-9a-f-]{36}$/i.test(args.scan_id))) {
      return toolResult({ error: "scan_id must be a valid scan identifier." }, true);
    }
    const aiRequest = new Request(new URL("/api/ai/assistant", request.url), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": request.headers.get("authorization") ?? ""
      },
      body: JSON.stringify({
        question: args.question,
        ...(typeof args.scan_id === "string" ? { scan_id: args.scan_id } : {})
      })
    });
    const aiResponse = await invokeHandler(assistantPost as any, aiRequest, env);
    const data = await aiResponse.json().catch(() => ({ error: "AI assistant returned an unreadable response." }));
    return toolResult(data, !aiResponse.ok);
  }

  return toolResult({ error: "Unknown Scam Detector tool." }, true);
}

export const onRequestOptions: PagesFunction<Env> = async () => new Response(null, { status: 204, headers: CORS_HEADERS });

export const onRequestGet: PagesFunction<Env> = async () =>
  response({ error: "This stateless MCP endpoint supports JSON-RPC POST requests only; server-sent events are not enabled." }, 405);

export const onRequestDelete: PagesFunction<Env> = async () =>
  response({ error: "This stateless MCP endpoint does not create sessions." }, 405);

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  if (!request.headers.get("content-type")?.toLowerCase().includes("application/json")) {
    return response({ error: "Content-Type must be application/json." }, 415);
  }

  let raw: string;
  try {
    raw = await request.text();
    if (new TextEncoder().encode(raw).byteLength > MAX_BODY) {
      return response({ error: "MCP request body is too large." }, 413);
    }
  } catch {
    return response({ error: "Could not read MCP request." }, 400);
  }

  let message: any;
  try {
    message = JSON.parse(raw);
  } catch {
    return response({ error: "MCP request must be valid JSON." }, 400);
  }

  if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    return rpcError(null, -32600, "Invalid JSON-RPC request.");
  }

  const id = typeof message.id === "string" || typeof message.id === "number" ? message.id : null;
  const isNotification = !("id" in message);

  if (message.method === "notifications/initialized" || message.method.startsWith("notifications/")) {
    return new Response(null, { status: 202, headers: CORS_HEADERS });
  }

  if (message.method === "initialize") {
    const requested = message.params?.protocolVersion;
    const protocolVersion = PROTOCOL_VERSIONS.includes(requested) ? requested : "2025-03-26";
    return rpc(id, {
      protocolVersion,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "scam-detector", version: "1.0.0", title: "Scam Detector Security Intelligence" },
      instructions: "Use investigate_website to obtain evidence first, then ask_scam_detector_ai for explanations and follow-up questions. Never treat a low score as proof of safety. Tool calls require a Scam Detector account API key."
    });
  }

  if (message.method === "ping") return rpc(id, {});

  if (message.method === "tools/list") {
    return rpc(id, { tools: TOOLS });
  }

  if (message.method === "tools/call") {
    const name = message.params?.name;
    const args = message.params?.arguments ?? {};
    if (typeof name !== "string" || !args || typeof args !== "object" || Array.isArray(args)) {
      return rpcError(id, -32602, "Invalid tool name or arguments.");
    }
    const result = await callTool(name, args as Record<string, unknown>, request, env);
    const payload = await result.json() as { result?: unknown };
    return rpc(id, payload.result);
  }

  if (isNotification) return new Response(null, { status: 202, headers: CORS_HEADERS });
  return rpcError(id, -32601, "Method not found.");
};
