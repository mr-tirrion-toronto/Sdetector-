# Evidence manifest signing setup

Scam Detector can sign the SHA-256 digest of each server-side evidence manifest using Ed25519.

## Generate a key pair

Use Node.js 20 or later in the project folder:

```bash
node scripts/generate-evidence-signing-key.mjs
```

The script prints three values:
- `EVIDENCE_SIGNING_PRIVATE_KEY`: PKCS#8 DER encoded as base64. Store this as a **Cloudflare Pages production secret**. Never commit it, put it in browser code, or paste it into a chat.
- `EVIDENCE_SIGNING_PUBLIC_KEY`: SPKI DER encoded as base64. This is public verification material.
- `EVIDENCE_SIGNING_KEY_ID`: public key identifier.

## Configure Cloudflare Pages

In Cloudflare Dashboard, open Workers & Pages → `mr-tirrion-scam-detector` → Settings → Environment variables → Production.

Add:
1. `EVIDENCE_SIGNING_PRIVATE_KEY` as a Secret.
2. `EVIDENCE_SIGNING_PUBLIC_KEY` as a plain-text variable.
3. `EVIDENCE_SIGNING_KEY_ID` as a plain-text variable.

Save and trigger a new production deployment. Do not replace or remove the existing database, AI or feed secrets.

## What is signed

The server signs the UTF-8 hexadecimal SHA-256 digest string of the canonical JSON evidence manifest using Ed25519. The manifest signature is stored with the public key and key ID. The API verifies the signature before reporting it as valid. A `manifest_signed` custody event records the signing operation.

The private key is never stored in Neon or returned by the API. The public key and signature can be included in a report and independently verified using OpenSSL or another Ed25519 implementation.

## Important limits

A valid signature proves that the holder of the corresponding private key signed that manifest digest. It does not prove that the underlying scan was complete, that the website content was truthful, that the examiner is qualified, or that a court must admit the report. Protect the private key, retain the public key independently, and obtain legal/forensic review.
