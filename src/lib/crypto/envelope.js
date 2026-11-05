// Message envelopes. Each message gets a fresh 256-bit content key. The content is
// AES-256-GCM encrypted once; the content key is sealed separately to each
// recipient account's current encryption key. Everything is bound to the exact
// conversation, item, sender and device it belongs to, so nothing can be moved
// between messages or conversations without failing to decrypt.
//
// AES-GCM doesn't commit to its key: a dishonest sender could seal different content
// keys to different members that open one ciphertext to different texts. So the
// envelope carries a hash of the content key (kc), covered by the sender's signature,
// and every recipient checks the key they unwrapped against it.
//
// Version 3 seals the content key with the post-quantum hybrid (kem.js) to every recipient whose
// current key has one ({u, kv, kct, iv, wk}); anyone else still gets a classical wrap
// ({u, kv, epk, iv, wk}). Version 2 envelopes, all classical, still open.
import { CryptoFormatError, concatBytes, equalBytes, fromB64, fromUtf8, randomBytes, sha256, toB64, utf8 } from "./encoding.js";
import { aesDecrypt, aesEncrypt, aesKeyFromBytes, importEcdhPrivate, openSealed, sealTo } from "./primitives.js";
import { keyForVersion } from "./keyring.js";
import { KEM_CIPHERTEXT_BYTES, kemOpen, kemSeal } from "./kem.js";

export const ENVELOPE_VERSION = 3;
const READABLE_VERSIONS = new Set([2, 3]);
export const MAX_RECIPIENTS = 32;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export class EnvelopeError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "EnvelopeError";
    this.code = code;
  }
}

function checkScope(scope) {
  if (!scope || (scope.kind !== "message" && scope.kind !== "title" && scope.kind !== "report")) {
    throw new EnvelopeError("BAD_SCOPE", "Unknown item kind");
  }
  for (const name of ["conversation_id", "item_id", "sender_id", "device_id"]) {
    if (typeof scope[name] !== "string" || !ID_RE.test(scope[name])) {
      throw new EnvelopeError("BAD_SCOPE", `Invalid ${name}`);
    }
  }
}

const contentContext = (s) =>
  `commonveil/content/v1|${s.kind}|${s.conversation_id}|${s.item_id}|${s.sender_id}|${s.device_id}`;

const wrapContext = (s, userId, keyVersion) =>
  `commonveil/wrap/v1|${s.kind}|${s.conversation_id}|${s.item_id}|${userId}|${keyVersion}`;

async function keyCommitment(scope, contentKeyBytes) {
  return sha256(concatBytes(utf8(`commonveil/key-commitment/v1|${contentContext(scope)}|`), contentKeyBytes));
}

function b64Length(value, exact, min) {
  const bytes = fromB64(value);
  if (exact !== undefined && bytes.length !== exact) throw new CryptoFormatError("Wrong length");
  if (min !== undefined && bytes.length < min) throw new CryptoFormatError("Too short");
  return bytes;
}

export function validateEnvelope(envelope) {
  try {
    if (!envelope || typeof envelope !== "object" || !READABLE_VERSIONS.has(envelope.v)) throw new Error("version");
    b64Length(envelope.iv, 12);
    b64Length(envelope.ct, undefined, 17);
    b64Length(envelope.kc, 32);
    if (!Array.isArray(envelope.wraps) || envelope.wraps.length === 0 || envelope.wraps.length > MAX_RECIPIENTS) {
      throw new Error("wraps");
    }
    const seen = new Set();
    for (const w of envelope.wraps) {
      if (!w || typeof w.u !== "string" || !ID_RE.test(w.u) || seen.has(w.u)) throw new Error("wrap user");
      if (!Number.isInteger(w.kv) || w.kv < 1) throw new Error("wrap version");
      if (w.kct !== undefined) {
        if (envelope.v < 3 || w.epk !== undefined) throw new Error("wrap kind");
        b64Length(w.kct, KEM_CIPHERTEXT_BYTES);
      } else {
        b64Length(w.epk, 65);
      }
      b64Length(w.iv, 12);
      b64Length(w.wk, 48);
      seen.add(w.u);
    }
  } catch {
    throw new EnvelopeError("BAD_ENVELOPE", "The encrypted message is malformed.");
  }
  return envelope;
}

export function parseEnvelope(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new EnvelopeError("BAD_ENVELOPE", "The encrypted message is malformed.");
  }
  return validateEnvelope(parsed);
}

/**
 * recipients: [{ user_id, key_version, ecdh_pub, kem_pub? }] - one entry per member account,
 * including the sender's own account so their other devices can read it. kem_pub (from the
 * recipient's verified key history) means a post-quantum wrap.
 */
export async function encryptEnvelope({ scope, recipients, payload }) {
  checkScope(scope);
  if (!Array.isArray(recipients) || recipients.length === 0 || recipients.length > MAX_RECIPIENTS) {
    throw new EnvelopeError("BAD_RECIPIENTS", "A message needs between 1 and 32 recipients.");
  }
  const contentKeyBytes = randomBytes(32);
  try {
    const contentKey = await aesKeyFromBytes(contentKeyBytes);
    const { iv, ct } = await aesEncrypt(contentKey, utf8(JSON.stringify(payload)), utf8(contentContext(scope)));
    const seen = new Set();
    const wraps = [];
    for (const r of recipients) {
      if (typeof r.user_id !== "string" || !ID_RE.test(r.user_id) || !Number.isInteger(r.key_version) || r.key_version < 1) {
        throw new EnvelopeError("BAD_RECIPIENTS", "Invalid recipient");
      }
      if (seen.has(r.user_id)) throw new EnvelopeError("BAD_RECIPIENTS", "Duplicate recipient");
      seen.add(r.user_id);
      const context = wrapContext(scope, r.user_id, r.key_version);
      if (r.kem_pub) {
        const sealed = await kemSeal(r.kem_pub, contentKeyBytes, context);
        wraps.push({ u: r.user_id, kv: r.key_version, kct: sealed.kct, iv: sealed.iv, wk: sealed.ct });
      } else {
        const sealed = await sealTo(r.ecdh_pub, contentKeyBytes, context);
        wraps.push({ u: r.user_id, kv: r.key_version, epk: sealed.epk, iv: sealed.iv, wk: sealed.ct });
      }
    }
    const kc = toB64(await keyCommitment(scope, contentKeyBytes));
    return { v: wraps.some((w) => w.kct) ? ENVELOPE_VERSION : 2, iv: toB64(iv), ct: toB64(ct), kc, wraps };
  } finally {
    contentKeyBytes.fill(0);
  }
}

const privateKeyCache = new Map();

async function cachedEcdhPrivate(keyVersion) {
  const cacheKey = `${keyVersion.version}:${keyVersion.ecdh_pub}`;
  if (!privateKeyCache.has(cacheKey)) {
    if (privateKeyCache.size > 64) privateKeyCache.clear();
    privateKeyCache.set(cacheKey, await importEcdhPrivate(keyVersion.ecdh_priv));
  }
  return privateKeyCache.get(cacheKey);
}

export function clearEnvelopeKeyCache() {
  privateKeyCache.clear();
}

export async function decryptEnvelope({ scope, envelope, userId, keyring }) {
  checkScope(scope);
  const env = typeof envelope === "string" ? parseEnvelope(envelope) : validateEnvelope(envelope);
  const wrap = env.wraps.find((w) => w.u === userId);
  if (!wrap) throw new EnvelopeError("NOT_ADDRESSED", "This item wasn't encrypted for your account.");
  const keyVersion = keyForVersion(keyring, wrap.kv);
  if (!keyVersion) {
    throw new EnvelopeError("KEY_VERSION_MISSING", "This item was encrypted to an account key this device doesn't hold.");
  }
  let contentKeyBytes;
  try {
    const context = wrapContext(scope, userId, wrap.kv);
    if (wrap.kct) {
      if (!keyVersion.kem_priv) throw new Error("no post-quantum key");
      contentKeyBytes = await kemOpen(keyVersion.kem_priv, { kct: wrap.kct, iv: wrap.iv, ct: wrap.wk }, context);
    } else {
      contentKeyBytes = await openSealed(await cachedEcdhPrivate(keyVersion), keyVersion.ecdh_pub, { epk: wrap.epk, iv: wrap.iv, ct: wrap.wk }, context);
    }
  } catch {
    throw new EnvelopeError("UNWRAP_FAILED", "This item's key failed its integrity check.");
  }
  if (contentKeyBytes.length !== 32) throw new EnvelopeError("UNWRAP_FAILED", "This item's key is malformed.");
  // Everyone must be opening the same message: the key has to match the one the sender committed to.
  if (!equalBytes(await keyCommitment(scope, contentKeyBytes), fromB64(env.kc))) {
    contentKeyBytes.fill(0);
    throw new EnvelopeError("KEY_COMMITMENT_FAILED", "This item's key doesn't match the one its sender committed to.");
  }
  const contentKey = await aesKeyFromBytes(contentKeyBytes);
  contentKeyBytes.fill(0);
  let plaintext;
  try {
    plaintext = await aesDecrypt(contentKey, fromB64(env.iv), fromB64(env.ct), utf8(contentContext(scope)));
  } catch {
    throw new EnvelopeError("DECRYPT_FAILED", "This item failed its integrity check.");
  }
  try {
    return JSON.parse(fromUtf8(plaintext));
  } catch {
    throw new EnvelopeError("DECRYPT_FAILED", "This item's contents are malformed.");
  }
}
