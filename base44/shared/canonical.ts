// Server copy of src/lib/crypto/canonical.js. Must stay byte-identical in output.
// tests/crypto.test.mjs runs both against the same inputs.

const CONTEXT_RE = /^[a-z0-9-]+\/v[0-9]+$/;

export const CONTEXTS = Object.freeze({
  accountKey: "account-key/v1",
  deviceCert: "device-cert/v1",
  deviceProof: "device-proof/v1",
  item: "item/v1",
  // Keyed with a secret only the recovery phrase produces, so the server can't check it.
  recoveryAnchor: "recovery-anchor/v1",
});

export function canonical(context: string, fields: string[]): string {
  if (!CONTEXT_RE.test(context)) throw new Error("Invalid signing context");
  if (!Array.isArray(fields)) throw new TypeError("Fields must be an array");
  for (const field of fields) {
    if (typeof field !== "string") throw new TypeError("Signed fields must be strings");
    if (/[\r\n]/.test(field)) throw new Error("Signed fields cannot contain line breaks");
  }
  return `commonveil/${context}\n${fields.length}\n${fields.join("\n")}`;
}

export const accountKeyFields = (s: any): string[] => [
  s.user_id,
  String(s.version),
  s.ecdh_pub,
  s.sign_pub,
  s.recovery_pub,
  String(s.signed_by_version),
  s.issued_at,
];

export const deviceCertFields = (c: any): string[] => [
  c.user_id,
  c.device_id,
  c.sign_pub,
  c.box_pub,
  String(c.key_version),
  c.issued_at,
];

export const deviceProofFields = (p: any): string[] => [
  p.user_id,
  p.device_id,
  p.action,
  p.payload_hash,
  p.issued_at,
  p.nonce,
];

export const itemFields = (m: any): string[] => [
  m.kind,
  m.conversation_id,
  m.item_id,
  m.sender_id,
  m.device_id,
  m.envelope_hash,
  m.sent_at,
];
