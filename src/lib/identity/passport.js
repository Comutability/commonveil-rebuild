// An identity passport: everything that makes an account *yours*, in one file you keep.
//
// The account is owned by a key derived from your recovery phrase, not by this site
// (docs/IDENTITY.md). A passport is that ownership, written down so any Commonveil site can check
// it without asking the site you're leaving:
//
//   - the owner key, in a quantum-resistant form (Ed25519 + ML-DSA-65). The phrase is the same
//     one you already have; the post-quantum half is derived from it with a different label, so
//     there's nothing new to remember.
//   - the account's key chain and its move history, each move signed by your owner key, in order,
//     so no site can present an older state of your account as the current one.
//   - a zero-knowledge proof that whoever made the passport holds the owner key. It reveals
//     nothing: not the key, not where it was used, not what any other site learned.
//   - your contacts and your messages, sealed under a key from your phrase. Sites carry the file
//     but can't read a word of it; only your phrase opens it, on whichever site you land.
//
// The passport is deliberately a file rather than something a server holds: moving site is a
// choice you make, and the thing that proves it is the thing you carry. The protocol's inbox and
// outbox (docs/FEDERATION.md) stay the way sites reach each other; the passport never passes
// through a relay in a form a relay could read.
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ownerKeyPair } from "@/lib/crypto/owner";
import { hkdfBytes } from "@/lib/crypto/primitives";
import { b64u, fromB64u, sha256B64u, utf8 } from "../../../packages/secure-net/src/core/bytes.js";
import { canonicalBytes } from "../../../packages/secure-net/src/core/canonical.js";
import { checkSignature, keyId, sign } from "../../../packages/secure-net/src/core/signed.js";
import { checkOwnerProof, proveOwner } from "../../../packages/secure-net/src/identity/zk.js";
import { MIGRATION, acceptMigration, currentSite } from "../../../packages/secure-net/src/identity/portable.js";

export const PASSPORT_FORMAT = "commonveil-passport-1";
export const PASSPORT_KIND = "identity.passport";
const SEAL_SALT = "commonveil/passport/v1";

export class PassportError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PassportError";
    this.code = code;
  }
}

const digestOf = (body) => sha256B64u(canonicalBytes(body));

/**
 * The owner key for a phrase, in the quantum-resistant form. The Ed25519 half is the same key the
 * account already has; the ML-DSA-65 half comes from the same phrase.
 */
export async function ownerIdentity(phrase) {
  const pair = await ownerKeyPair(phrase);
  const pqPublicKey = b64u(ml_dsa65.keygen(pair.pqSeed).publicKey);
  const hybrid = `${pair.publicKey}.${pqPublicKey}`;
  return {
    ed25519: pair.publicKey,
    ml_dsa_65: pqPublicKey,
    hybrid,
    kid: keyId(hybrid),
    // What signed.js signs with: "<Ed25519 seed>.<ML-DSA-65 seed>", both base64url.
    signKey: { kid: keyId(hybrid), publicKey: hybrid, secretKey: `${b64u(pair.secret)}.${b64u(pair.pqSeed)}` },
    secret: pair.secret,
  };
}

// ---------- sealed parts ----------

async function sealKey(secret) {
  return hkdfBytes(secret, utf8(SEAL_SALT), "seal", 32);
}

async function seal(keyBytes, value) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, utf8(JSON.stringify(value)));
  return { iv: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}

async function unseal(keyBytes, sealed) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64u(sealed.iv) }, key, fromB64u(sealed.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

// ---------- the move history ----------

/** One move to another site, signed by the owner key. seq counts from 1 and only ever goes up. */
export function makeMove({ subject, from, to, seq, keepOldUntil = null }, signKey) {
  if (!Number.isSafeInteger(seq) || seq < 1) throw new PassportError("BAD_SEQ", "A move needs a position in the history from 1");
  if (!from || !to || from === to) throw new PassportError("BAD_SITES", "A move needs two different sites");
  return sign(MIGRATION, { subject, from, to, seq, at: new Date().toISOString(), keep_old_until: keepOldUntil }, signKey);
}

/** Where the account lives now, after its history (checked in order, stale moves ignored). */
export const siteAfter = (chain, ownerPub, start) => currentSite(chain || [], ownerPub, start);

/** The next sequence number for a history. */
export const nextSeq = (chain) => (chain || []).reduce((n, x) => Math.max(n, Number(x.body?.seq) || 0), 0) + 1;

// ---------- building one ----------

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

/**
 * Build a passport. `data` is the account's decrypted export (lib/secure/exportData.js); `chain`
 * is the move history so far. Nothing leaves the browser: this only returns the object to save.
 */
export async function buildPassport({ phrase, handle, home, profile, userId, keyVersion, chainHead, data, chain = [], onProgress = () => {} }) {
  if (!phrase) throw new PassportError("NO_PHRASE", "Your recovery phrase is what makes this passport yours.");
  onProgress("Opening your owner key");
  const owner = await ownerIdentity(phrase);
  try {
    onProgress("Sealing your contacts and messages");
    const sealBytes = await sealKey(owner.secret);
    const contacts = contactsFrom(data, userId);
    const sealedContacts = await seal(sealBytes, contacts);
    const sealedArchive = await seal(sealBytes, data);

    const messages = (data?.conversations || []).reduce((n, c) => n + (c.messages?.length || 0), 0);
    const body = {
      version: 1,
      handle: handle || "",
      home,
      profile: { username: profile?.username || "", display_name: profile?.display_name || "" },
      owner: { ed25519: owner.ed25519, ml_dsa_65: owner.ml_dsa_65, hybrid: owner.hybrid, kid: owner.kid },
      account: { user_id: userId, key_version: keyVersion ?? null, chain_head: chainHead || null },
      chain,
      parts: {
        contacts: { count: contacts.length },
        archive: { conversations: (data?.conversations || []).length, messages },
      },
      made_at: new Date().toISOString(),
    };

    onProgress("Signing it, twice");
    const record = sign(PASSPORT_KIND, body, owner.signKey);
    const proof = proveOwner(owner.secret, owner.ed25519, { purpose: "passport", handle: body.handle, digest: digestOf(body) });
    return { format: PASSPORT_FORMAT, record, proof, sealed: { contacts: sealedContacts, archive: sealedArchive } };
  } finally {
    owner.secret.fill(0);
  }
}

// ---------- reading one ----------

/** Read a passport file's structure. Throws for anything that isn't one. */
export function readPassport(file) {
  let doc = file;
  if (typeof file === "string") {
    try {
      doc = JSON.parse(file);
    } catch {
      throw new PassportError("MALFORMED", "That file isn't a Commonveil passport.");
    }
  }
  if (!doc || doc.format !== PASSPORT_FORMAT || !doc.record?.body || !doc.record?.sig) {
    throw new PassportError("MALFORMED", "That file isn't a Commonveil passport.");
  }
  if (!doc.sealed?.contacts || !doc.sealed?.archive) throw new PassportError("MALFORMED", "This passport is missing its contents.");
  return doc;
}

/**
 * Check a passport without opening it: the quantum-resistant signature, the zero-knowledge proof,
 * and the move history. Answers { ok, body, problems }. Reading the contents needs the phrase.
 */
export function verifyPassport(file) {
  const doc = readPassport(file);
  const body = doc.record.body;
  const problems = [];
  const owner = body.owner || {};

  if (doc.record.kind !== PASSPORT_KIND) problems.push("It isn't marked as an identity passport.");
  if (!owner.hybrid || !owner.ed25519 || !owner.ml_dsa_65) problems.push("It doesn't carry a quantum-resistant owner key.");
  else if (owner.hybrid !== `${owner.ed25519}.${owner.ml_dsa_65}`) problems.push("Its owner key halves don't belong together.");
  if (owner.hybrid && keyId(owner.hybrid) !== owner.kid) problems.push("Its owner key doesn't match its own name.");
  if (doc.record.sig?.kid !== owner.kid) problems.push("It's signed by something other than its owner key.");
  if (owner.hybrid && !checkSignature(doc.record, doc.record.sig, owner.hybrid)) {
    problems.push("Its signature doesn't hold up: it was changed, or the quantum-resistant half is missing.");
  }

  const proofOk = owner.ed25519 && checkOwnerProof(doc.proof, owner.ed25519, { purpose: "passport", handle: body.handle, digest: digestOf(body) });
  if (!proofOk) problems.push("Its zero-knowledge proof doesn't hold: whoever made it didn't show they hold the key.");

  let site = body.home;
  let last = null;
  for (const notice of [...(body.chain || [])].sort((a, b) => (a.body?.seq || 0) - (b.body?.seq || 0))) {
    try {
      last = acceptMigration(notice, owner.hybrid, last);
      site = last.to;
    } catch {
      problems.push("Its move history has a step that doesn't follow from the one before.");
      break;
    }
  }
  if (site !== body.home) problems.push("Its move history ends somewhere other than where it says it lives.");

  return { ok: problems.length === 0, body, problems };
}

/**
 * Open a passport with the phrase: proves the phrase is the owner's, then hands back the contacts
 * and the archive. Nothing is sent anywhere, and the destination site learns nothing by this.
 */
export async function openPassport(file, phrase) {
  const verdict = verifyPassport(file);
  if (!verdict.ok) throw new PassportError("INVALID", verdict.problems[0]);
  const owner = await ownerIdentity(phrase);
  try {
    if (owner.hybrid !== verdict.body.owner.hybrid) throw new PassportError("WRONG_PHRASE", "That's not the phrase this passport was made with.");
    const sealBytes = await sealKey(owner.secret);
    let contacts;
    let data;
    try {
      contacts = await unseal(sealBytes, file.sealed.contacts);
      data = await unseal(sealBytes, file.sealed.archive);
    } catch {
      throw new PassportError("CANNOT_OPEN", "This passport's contents can't be opened. It may have been changed after it was made.");
    }
    return { body: verdict.body, contacts, data };
  } finally {
    owner.secret.fill(0);
  }
}

/** A short name for a key, to compare out loud: first 8 characters, in fours. */
export const fingerprint = (publicKey) => {
  const id = keyId(String(publicKey || ""));
  return `${id.slice(0, 4)} ${id.slice(4, 8)}`;
};