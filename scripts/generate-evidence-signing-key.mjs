import { generateKeyPairSync } from "node:crypto";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const privateKeyBase64 = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const publicKeyBase64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
const keyId = "scam-detector-ed25519-" + new Date().toISOString().slice(0, 10).replace(/-/g, "");

console.log("Create these Cloudflare Pages production variables:");
console.log("");
console.log("EVIDENCE_SIGNING_PRIVATE_KEY (SECRET — never commit or share):");
console.log(privateKeyBase64);
console.log("");
console.log("EVIDENCE_SIGNING_PUBLIC_KEY (plain text):");
console.log(publicKeyBase64);
console.log("");
console.log("EVIDENCE_SIGNING_KEY_ID (plain text):");
console.log(keyId);
console.log("");
console.log("Store the private key only as a Cloudflare secret. Keep a secure offline backup under your control.");
