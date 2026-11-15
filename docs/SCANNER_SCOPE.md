# Scanner Scope

## Implemented in version 0.2 (after the confidence and API-hardening release is merged and deployed)

- Strict URL parsing and HTTP/HTTPS scheme allow-list.
- URL-pattern heuristics for HTTP, deceptive authority/userinfo syntax, punycode labels, IP-literal hosts, deep subdomains, long hostnames, known shorteners, sensitive-action terms and non-standard ports.
- Explainable findings with evidence, severity, points and recommendations.
- A bounded 0–100 URL-signal score.
- Explicit assessment state: no configured signals means **insufficient evidence**, not verified safe.
- Limited confidence label and visible capability limitations.
- Streaming request-body byte limit.
- Per-client rate limit using a short-lived SHA-256 bucket key from the Cloudflare client IP.
- Atomic single-statement persistence of a scan and its findings.
- Redaction of URL userinfo, fragments and common sensitive query values before database storage.
- Live API/database health status in the interface.
- PDF via browser print and copyable scan summary.

## Not implemented yet

The scanner still does not fetch submitted websites, resolve DNS, inspect TLS certificates, determine domain age, follow redirects, query third-party reputation providers, parse page content, identify brand impersonation, monitor changes, or generate a server-authored PDF report. Local browser history is not a server-side investigation history dashboard.

## Threat intelligence status

No external threat feed is currently integrated. OpenPhish Community Feed terms currently restrict use to personal/academic research and prohibit product development or commercial use without written permission. URLhaus community bulk exports require an Auth-Key and commercial use may require the enhanced paid API. PhishTank API/data documentation and terms need current Cisco permission review and a registered application key before production integration. Do not silently use or redistribute a feed without verifying its current terms.

The weekly security review task is for advisory and provider-change monitoring; it does not itself update the scanner's production threat database.

## Safety boundary

The scanner does not fetch submitted URLs and does not execute third-party page code. Any future active inspection must have destination validation at connection time, DNS rebinding protection, private/reserved address blocking, redirect re-validation, strict time/size limits, and isolated parsing. DNS checks through a fixed trusted resolver endpoint may be added separately; they must not be described as live page inspection.

A zero score means only that the configured URL heuristics produced no points. It is not a safety guarantee, probability, or reputation verdict.
