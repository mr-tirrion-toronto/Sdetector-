# Scam Detector AI and External Tool API

## Overview

Scam Detector exposes an evidence-first API for people, applications and AI assistants. It provides:

- Website investigation through `POST /api/scan`.
- AI explanations and follow-up questions through `POST /api/ai/assistant`.
- Machine-readable API discovery through `/openapi.json`, suitable for API clients and custom GPT Actions.
- Account-scoped API keys. The caller's Scam Detector key is separate from the server-side OpenAI credential.

## Configure the OpenAI credential

In Cloudflare Dashboard, open **Workers & Pages → mr-tirrion-scam-detector → Settings → Variables and Secrets → Production**. Add a secret named `OPENAI_API_KEY` and paste the existing OpenAI Platform key into the secret-value field. Never commit the value, place it in a browser bundle, or send it in chat.

Optional non-secret variable: `OPENAI_MODEL`. If omitted, the assistant uses `gpt-4.1-mini`.

## Secondary AI provider (recommended)
The backend supports Google Gemini as a fallback when OpenAI is rate-limited, out of quota, or temporarily unavailable. Add a Google AI Studio API key as a Cloudflare Pages **Production secret** named `GEMINI_API_KEY`. Do not put this key in GitHub, browser code, or chat. Optional non-secret variable: `GEMINI_MODEL`; the default is `gemini-2.5-flash`.

The fallback uses the same evidence-only safety instructions and sends no credentials other than the provider key in the server-side request header. OpenAI remains the primary provider; Gemini is used only when needed. Separate API providers have separate billing and quota policies.

After saving the secret, redeploy the Pages project so the production deployment receives the binding. Preview deployments require a separate preview secret if you want to test there.

## Authentication

AI requests require either a signed-in Scam Detector session cookie or an account API key:

```http
Authorization: Bearer sd_live_YOUR_SCAM_DETECTOR_ACCOUNT_KEY
```

Create and revoke these keys in `/account.html`. They are not OpenAI API keys. Never send the OpenAI credential to an API consumer.

## Workflow for AI agents

### 1. Investigate a URL

```http
POST /api/scan
Content-Type: application/json
Authorization: Bearer sd_live_...
```

```json
{ "url": "https://example.com" }
```

The response contains a `scanId`, a risk indicator, findings, evidence, source statuses, limitations and advanced intelligence. Save the `scanId`.

### 2. Ask a question about the saved investigation

```http
POST /api/ai/assistant
Content-Type: application/json
Authorization: Bearer sd_live_...
```

```json
{
  "scan_id": "SCAN_UUID_FROM_STEP_1",
  "question": "Explain the strongest warning signs and what I should do next."
}
```

The assistant only retrieves scans owned by the authenticated account. It will not access another user's scans. A caller can omit `scan_id` to ask general questions about Scam Detector's documented capabilities.

## Rate limits and privacy

- AI assistant: 12 requests per account per 10-minute window.
- Scan endpoint has its own IP-based rate limit.
- AI output is generated with the OpenAI Responses API and `store: false`.
- The server sends structured scan evidence and the user's question to OpenAI; it does not send the user's OpenAI key to the browser or caller.
- Do not submit passwords, payment details, OTPs, recovery phrases, private tokens or other secrets in URLs or questions.
- AI output is explanatory and may be wrong. It is not a substitute for independent verification or incident response.

## Model Context Protocol (MCP) server

The project also exposes a stateless Streamable HTTP MCP endpoint at `POST /mcp`. It advertises three tools:

- `investigate_website` — run the existing full website investigation.
- `ask_scam_detector_ai` — ask the evidence-grounded assistant about a saved scan or the service.
- `get_scanner_health` — check API and database health.

The MCP server supports the Streamable HTTP JSON-RPC lifecycle and requires a Scam Detector account API key for investigation and AI tools. In a compatible MCP client, connect to `https://scam-detector-a92.pages.dev/mcp` and choose API-key authentication with the Bearer scheme. Use a Scam Detector `sd_live_...` key from the account workspace. The health tool is available without authentication.

## Integrating a custom GPT

Import `https://scam-detector-a92.pages.dev/openapi.json` into the custom GPT's Actions configuration. Configure authentication as API Key → Bearer and use a Scam Detector account API key. Keep the OpenAI Platform key exclusively in Cloudflare.

ChatGPT will not automatically gain access to this service merely because the API exists; install and authorize the Scam Detector MCP plugin or configure a GPT Action. Each user must authorize access with their own Scam Detector account API key.
