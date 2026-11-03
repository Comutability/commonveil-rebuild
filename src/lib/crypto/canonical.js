// Canonical text for every signed statement.
// The server keeps a byte-identical copy in base44/shared/canonical.ts.
// tests/crypto.test.mjs checks that both produce the same output.

const CONTEXT_RE = /^[a-z0-9-]+\/v[0-9]+$/;

export const CONTEXTS = Object.freeze({
  accountKey: "account-key/v1",
  // The same statement for a key version that also has a post-quantum (ML-KEM-768 + P-256) key.
  accountKeyPq: "account-key/v2",
  deviceCert: "device-cert/v1",
  deviceCertPq: "device-cert/v2",
  // A device's own signature over its post-quantum key, for devices set up before they had one.
  deviceKem: "device-kem/v1",
  deviceProof: "device-proof/v1",
  item: "item/v1",
  // Keyed with a secret only the recovery phrase produces (see recovery.js).
  recoveryAnchor: "recovery-anchor/v1",
  recoveryAnchorPq: "recovery-anchor/v2",
  // Servers: a key generation's commitment, a key grant, an encrypted server item, a voice offer.
  chainGeneration: "chain-gen/v1",
  keyGrant: "key-grant/v1",
  serverItem: "server-item/v1",
  voiceHello: "voice-hello/v1",
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

/** The same, for a key version with a post-quantum key (and, if set, a post-quantum recovery key). */
export const accountKeyFieldsPq = (s) => [
  s.user_id,
  String(s.version),
  s.ecdh_pub,
  s.sign_pub,
  s.kem_pub,
  s.recovery_pub,
  s.recovery_kem_pub || "",
  String(s.signed_by_version),
  s.issued_at,
];

const hasKem = (x) => typeof x?.kem_pub === "string" && x.kem_pub.length > 0;

/**
 * The text a statement is signed over. Which form applies follows from the statement itself:
 * removing or adding a post-quantum key changes the text, so the signature no longer verifies.
 */
export const statementText = (s) =>
  hasKem(s) ? canonical(CONTEXTS.accountKeyPq, accountKeyFieldsPq(s)) : canonical(CONTEXTS.accountKey, accountKeyFields(s));

/** The text a recovery anchor is an HMAC over. */
export const anchorText = (s) =>
  hasKem(s) ? canonical(CONTEXTS.recoveryAnchorPq, accountKeyFieldsPq(s)) : canonical(CONTEXTS.recoveryAnchor, accountKeyFields(s));

/** Certificate binding a device's keys to an account key version. */
export const deviceCertFields = (c) => [
  c.user_id,
  c.device_id,
  c.sign_pub,
  c.box_pub,
  String(c.key_version),
  c.issued_at,
];

export const deviceCertFieldsPq = (c) => [
  c.user_id,
  c.device_id,
  c.sign_pub,
  c.box_pub,
  c.kem_pub,
  String(c.key_version),
  c.issued_at,
];

export const certText = (c) =>
  hasKem(c) ? canonical(CONTEXTS.deviceCertPq, deviceCertFieldsPq(c)) : canonical(CONTEXTS.deviceCert, deviceCertFields(c));

export const deviceKemFields = (d) => [d.user_id, d.device_id, d.kem_pub];

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

/** A new key generation for one of a server's key chains: who made it, when it starts, and a hash of its key. */
export const chainGenerationFields = (g) => [
  g.server_id,
  g.chain_id,
  String(g.generation),
  g.started_at,
  g.commit,
  g.creator_id,
  g.device_id,
];

/** One member's sealed copy of a server key. */
export const keyGrantFields = (g) => [
  g.server_id,
  g.chain_id,
  String(g.generation),
  String(g.step),
  g.recipient_id,
  String(g.recipient_key_version),
  g.sealed_hash,
  g.grantor_id,
  g.grantor_device_id,
  g.granted_at,
];

/** Signature over an encrypted server item: a message, a channel or server name, a nickname. */
export const serverItemFields = (m) => [
  m.kind,
  m.server_id,
  m.channel_id,
  m.item_id,
  m.sender_id,
  m.device_id,
  m.envelope_hash,
  m.sent_at,
];

/** A device's offer to join a voice call, binding its WebRTC certificate fingerprint. */
export const voiceHelloFields = (v) => [
  v.room,
  v.user_id,
  v.device_id,
  v.peer_id,
  v.fingerprint,
  v.issued_at,
];
