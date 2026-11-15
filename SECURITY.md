# Security Policy

## Supported versions
Until the first tagged release, security fixes are made against the default branch.

## Reporting a vulnerability
Please do not disclose security vulnerabilities publicly in GitHub issues.

Contact the project maintainer privately through the contact method listed on the repository owner's GitHub profile. Include a clear description and impact, safe reproduction steps, affected component and suggested mitigation if known.

Do not include passwords, access tokens, personal data or third-party secrets in a report.

## Scanner safety
The URL scanner must treat every submitted URL and fetched response as untrusted input. SSRF, DNS rebinding, redirect abuse, decompression bombs, oversized responses and content-parser vulnerabilities are in-scope security concerns.
