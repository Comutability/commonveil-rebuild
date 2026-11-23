// Experimental, file-only identity backup. This is NOT a live migration or a zero-knowledge proof.
// Secure Net's frozen 0.5.0 compatibility package must never be modified to add app features.
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ownerKey, privateKeyFromPhrase } from "@/lib/crypto/owner";
import { hkdfBytes } from "@/lib/crypto/primitives";
import { b64u, fromB64u, sha256B64u, utf8 } from "../../../packages/secure-net/src/core/bytes.js";
import { canonicalBytes } from "../../../packages/secure-net/src/core/canonical.js";
import { checkSignature, keyId, sign } from "../../../packages/secure-net/src/core/signed.js";

export const PASSPORT_FORMAT = "commonveil-passport-2";
export const PASSPORT_KIND = "identity.passport";
const SALT = "commonveil/passport/v2";
const MAX_ARCHIVE_SIZE = 128 * 1024 * 1024;

export class PassportError extends Error {
  constructor(code, message) { super(message); this.name = "PassportError"; this.code = code; }
}

// Derive a distinct ML-DSA-65 identity key from the same 256-bit owner entropy.
// This signs the backup; it does NOT upgrade site authentication or an existing actor's keys.
export async function ownerIdentity(phrase) {
  const classical = await ownerKey(phrase);
  const encoded = privateKeyFromPhrase(phrase);
  const entropy = fromB64u(encoded.slice("cvkey1".length)).slice(0, 32);
  let pqSeed;
  try {
    pqSeed = await hkdfBytes(entropy, utf8("commonveil/owner/v1"), "ml-dsa-65", 32);
    const pqPublicKey = b64u(ml_dsa65.keygen(pqSeed).publicKey);
    const hybrid = `${classical.publicKey}.${pqPublicKey}`;
    const kid = keyId(hybrid);
    return {
      ed25519: classical.publicKey, ml_dsa_65: pqPublicKey, hybrid, kid,
      signKey: { kid, publicKey: hybrid, secretKey: `${b64u(classical.secret)}.${b64u(pqSeed)}` },
      secret: classical.secret,
    };
  } finally {
    entropy.fill(0);
    pqSeed?.fill(0);
  }
}

async function sealKey(secret) {
  return hkdfBytes(secret, utf8(SALT), "seal", 32);
}

const aad = (actorId, part) => utf8(`${SALT}/${actorId}/${part}`);

async function seal(keyBytes, value, actorId, part) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(actorId, part) }, key, utf8(JSON.stringify(value)));
  return { iv: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}

async function unseal(keyBytes, sealed, actorId, part) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64u(sealed.iv), additionalData: aad(actorId, part) }, key, fromB64u(sealed.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

const contactsFrom = (data, selfId) => {
  const seen = new Map();
  for (const c of data?.conversations || []) {
    for (const m of c.members || []) {
      if (m.you || !m.user_id || m.user_id === selfId) continue;
      if (!seen.has(m.user_id)) seen.set(m.user_id, { user_id: m.user_id, username: m.username || null, display_name: m.display_name || "" });
    }
  }
  return [...seen.values()];
};

/** Build a signed, authenticated, client-encrypted read-only copy of accessible data. */
export async function buildPassport({ phrase, handle, home, profile, userId, keyVersion, chainHead, data, onProgress = () => {} }) {
  if (!phrase) throw new PassportError("NO_PHRASE", "Enter your recovery phrase to encrypt the archive.");
  if (!data || !Array.isArray(data.conversations)) throw new PassportError("BAD_DATA", "Your messages could not be collected.");
  const owner = await ownerIdentity(phrase);
  let key;
  try {
    onProgress("Encrypting your accessible history");
    key = await sealKey(owner.secret);
    const contacts = contactsFrom(data, userId);
    const sealedContacts = await seal(key, contacts, owner.kid, "contacts");
    const sealedArchive = await seal(key, data, owner.kid, "archive");
    const messages = data.conversations.reduce((n, c) => n + (c.messages?.length || 0), 0);
    const body = {
      version: 2,
      handle: handle || "",
      home: home || "",
      profile: { username: profile?.username || "", display_name: profile?.display_name || "" },
      owner: { ed25519: owner.ed25519, ml_dsa_65: owner.ml_dsa_65, hybrid: owner.hybrid, kid: owner.kid },
      source: { user_id: userId || "", key_version: keyVersion ?? null, chain_head: chainHead || null },
      parts: {
        contacts: { count: contacts.length, digest: sha256B64u(canonicalBytes(sealedContacts)) },
        archive: { conversations: data.conversations.length, messages, digest: sha256B64u(canonicalBytes(sealedArchive)) },
      },
      made_at: new Date().toISOString(),
    };
    onProgress("Signing the encrypted archive");
    return { format: PASSPORT_FORMAT, record: sign(PASSPORT_KIND, body, owner.signKey), sealed: { contacts: sealedContacts, archive: sealedArchive } };
  } finally {
    owner.secret.fill(0);
    owner.signKey.secretKey = "";
    key?.fill(0);
  }
}

export function readPassport(file) {
  let doc = file;
  if (typeof file === "string") {
    if (file.length > MAX_ARCHIVE_SIZE) throw new PassportError("TOO_LARGE", "This archive exceeds the maximum size supported by this preview.");
    try { doc = JSON.parse(file); } catch { throw new PassportError("MALFORMED", "That is not a valid identity archive."); }
  }
  if (!doc || doc.format !== PASSPORT_FORMAT || !doc.record?.body || !doc.record?.sig || !doc.sealed?.contacts || !doc.sealed?.archive) {
    throw new PassportError("MALFORMED", "This is not a supported identity archive.");
  }
  return doc;
}

export function verifyPassport(file) {
  const doc = readPassport(file);
  const body = doc.record.body;
  const owner = body.owner || {};
  const problems = [];
  try {
    if (doc.record.kind !== PASSPORT_KIND || body.version !== 2) problems.push("Unsupported record version.");
    if (typeof owner.ed25519 !== "string" || typeof owner.ml_dsa_65 !== "string" ||
        owner.hybrid !== `${owner.ed25519}.${owner.ml_dsa_65}` || keyId(owner.hybrid) !== owner.kid) {
      problems.push("Invalid hybrid signing key.");
    }
    if (doc.record.sig?.kid !== owner.kid || !checkSignature(doc.record, doc.record.sig, owner.hybrid)) {
      problems.push("Both owner signatures must verify.");
    }
    if (!doc.sealed?.contacts?.iv || !doc.sealed?.archive?.iv ||
        sha256B64u(canonicalBytes(doc.sealed.contacts)) !== body.parts?.contacts?.digest ||
        sha256B64u(canonicalBytes(doc.sealed.archive)) !== body.parts?.archive?.digest) {
      problems.push("Encrypted archive content has been changed.");
    }
  } catch {
    problems.push("This archive contains malformed signing or encrypted data.");
  }
  return { ok: problems.length === 0, body, problems };
}

export async function openPassport(file, phrase) {
  const doc = readPassport(file);
  const result = verifyPassport(doc);
  if (!result.ok) throw new PassportError("INVALID", result.problems[0]);
  const owner = await ownerIdentity(phrase);
  let key;
  try {
    if (owner.hybrid !== result.body.owner.hybrid) throw new PassportError("WRONG_PHRASE", "That recovery phrase does not open this archive.");
    key = await sealKey(owner.secret);
    const contacts = await unseal(key, doc.sealed.contacts, owner.kid, "contacts");
    const data = await unseal(key, doc.sealed.archive, owner.kid, "archive");
    if (!Array.isArray(contacts) || !Array.isArray(data?.conversations)) throw new PassportError("MALFORMED", "The decrypted archive is incomplete.");
    if (contacts.length !== result.body.parts.contacts.count || data.conversations.length !== result.body.parts.archive.conversations ||
        data.conversations.reduce((n, c) => n + (c.messages?.length || 0), 0) !== result.body.parts.archive.messages) {
      throw new PassportError("COUNTS", "The decrypted archive does not match its signed counts.");
    }
    return { body: result.body, contacts, data };
  } catch (error) {
    if (error instanceof PassportError) throw error;
    throw new PassportError("CANNOT_OPEN", "This archive could not be opened or its contents were changed.");
  } finally {
    owner.secret.fill(0);
    owner.signKey.secretKey = "";
    key?.fill(0);
  }
}

export const fingerprint = (publicKey) => {
  const id = keyId(String(publicKey || ""));
  return `${id.slice(0, 4)} ${id.slice(4, 8)}`;
};
