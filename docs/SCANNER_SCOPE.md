# Initial Scanner Scope

## Implemented in version 0.1

- Strict URL parsing and HTTP/HTTPS scheme allow-list.
- Heuristic checks for HTTP, URL user-information syntax, punycode labels, IP-literal hosts, deep subdomains, long hostnames, known shorteners, sensitive-action URL terms and non-standard ports.
- Explainable findings with evidence, severity, points and recommendations.
- A bounded 0–100 heuristic score and risk band.
- Optional persistence to PostgreSQL using Neon.
- Initial scan and finding tables.

## Not implemented yet

The initial scanner does not resolve DNS, connect to submitted websites, follow redirects, inspect TLS certificates, determine domain age, query reputation providers, parse page content, identify brand impersonation, monitor changes, generate PDF reports or provide user accounts.

## Safety boundary

The initial scanner does not fetch submitted URLs and does not execute third-party page code. This avoids turning the first release into an SSRF-capable proxy. Any future active-fetch feature must be designed with DNS rebinding resistance, destination IP validation at connection time, private/reserved address blocking, redirect re-validation, strict time and size limits, and isolated execution. Do not claim active website inspection until those controls are implemented and tested.
