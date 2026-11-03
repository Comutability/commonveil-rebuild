// Server copy of src/lib/crypto/canonical.js. Must stay byte-identical in output.
// tests/crypto.test.mjs runs both against the same inputs.

const CONTEXT_RE = /^[a-z0-9-]+\/v[0-9]+$/;

export const CONTEXTS = Object.freeze({
  accountKey: "account-key/v1",
  accountKeyPq: "account-key/v2",
  deviceCert: "device-cert/v1",
  deviceCertPq: "device-cert/v2",
  deviceKem: "device-kem/v1",
  deviceProof: "device-proof/v1",
  item: "item/v1",
  // Keyed with a secret only the recovery phrase produces, so the server can't check it.
  recoveryAnchor: "recovery-anchor/v1",
  recoveryAnchorPq: "recovery-anchor/v2",
  chainGeneration: "chain-gen/v1",
  keyGrant: "key-grant/v1",
  serverItem: "server-item/v1",
  voiceHello: "voice-hello/v1",
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

export const accountKeyFieldsPq = (s: any): string[] => [
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

const hasKem = (x: any) => typeof x?.kem_pub === "string" && x.kem_pub.length > 0;

export const statementText = (s: any): string =>
  hasKem(s) ? canonical(CONTEXTS.accountKeyPq, accountKeyFieldsPq(s)) : canonical(CONTEXTS.accountKey, accountKeyFields(s));

export const anchorText = (s: any): string =>
  hasKem(s) ? canonical(CONTEXTS.recoveryAnchorPq, accountKeyFieldsPq(s)) : canonical(CONTEXTS.recoveryAnchor, accountKeyFields(s));

export const deviceCertFields = (c: any): string[] => [
  c.user_id,
  c.device_id,
  c.sign_pub,
  c.box_pub,
  String(c.key_version),
  c.issued_at,
];

export const deviceCertFieldsPq = (c: any): string[] => [
  c.user_id,
  c.device_id,
  c.sign_pub,
  c.box_pub,
  c.kem_pub,
  String(c.key_version),
  c.issued_at,
];

export const certText = (c: any): string =>
  hasKem(c) ? canonical(CONTEXTS.deviceCertPq, deviceCertFieldsPq(c)) : canonical(CONTEXTS.deviceCert, deviceCertFields(c));

export const deviceKemFields = (d: any): string[] => [d.user_id, d.device_id, d.kem_pub];

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

export const chainGenerationFields = (g: any): string[] => [
  g.server_id,
  g.chain_id,
  String(g.generation),
  g.started_at,
  g.commit,
  g.creator_id,
  g.device_id,
];

export const keyGrantFields = (g: any): string[] => [
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

export const serverItemFields = (m: any): string[] => [
  m.kind,
  m.server_id,
  m.channel_id,
  m.item_id,
  m.sender_id,
  m.device_id,
  m.envelope_hash,
  m.sent_at,
];

export const voiceHelloFields = (v: any): string[] => [
  v.room,
  v.user_id,
  v.device_id,
  v.peer_id,
  v.fingerprint,
  v.issued_at,
];
