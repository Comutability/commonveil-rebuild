// Canonical text for every signed statement.
// The server keeps a byte-identical copy in base44/shared/canonical.ts.
// tests/crypto.test.mjs checks that both produce the same output.

const CONTEXT_RE = /^[a-z0-9-]+\/v[0-9]+$/;

export const CONTEXTS = Object.freeze({
  accountKey: "account-key/v1",
  deviceCert: "device-cert/v1",
  deviceProof: "device-proof/v1",
  item: "item/v1",
  // Keyed with a secret only the recovery phrase produces (see recovery.js).
  recoveryAnchor: "recovery-anchor/v1",
});

export function canonical(context, fields) {
  if (!CONTEXT_RE.test(context)) throw new Error("Invalid signing context");
  if (!Array.isArray(fields)) throw new TypeError("Fields must be an array");
  for (const field of fields) {
    if (typeof field !== "string") throw new TypeError("Signed fields must be strings");
    if (/[\r\n]/.test(field)) throw new Error("Signed fields cannot contain line breaks");
  }
  return `commonveil/${context}\n${fields.length}\n${fields.join("\n")}`;
}

/** Published account key statement (genesis, rotation or reset). */
export const accountKeyFields = (s) => [
  s.user_id,
  String(s.version),
  s.ecdh_pub,
  s.sign_pub,
  s.recovery_pub,
  String(s.signed_by_version),
  s.issued_at,
];

/** Certificate binding a device's keys to an account key version. */
export const deviceCertFields = (c) => [
  c.user_id,
  c.device_id,
  c.sign_pub,
  c.box_pub,
  String(c.key_version),
  c.issued_at,
];

/** Proof that a request came from a specific device. */
export const deviceProofFields = (p) => [
  p.user_id,
  p.device_id,
  p.action,
  p.payload_hash,
  p.issued_at,
  p.nonce,
];

/** Signature over an encrypted message or group title. */
export const itemFields = (m) => [
  m.kind,
  m.conversation_id,
  m.item_id,
  m.sender_id,
  m.device_id,
  m.envelope_hash,
  m.sent_at,
];
