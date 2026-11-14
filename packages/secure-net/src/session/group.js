// Group messages with sender keys (CVP-016, "Groups").
//
// Each member device has a sending chain per group. It sends the chain key to every other member
// device over their one-to-one sessions (which are post-quantum), then encrypts each group
// message once. Keys move forward with every message, so a stolen key can't read earlier ones.
// When anyone leaves, every remaining member makes a new sender key and sends it only to those
// still in the group, so the person who left can't read what comes next.
//
// Each message is also signed with the sender's Ed25519 key, so one member can't pass off a
// message as another's. Forging that signature would take a quantum computer at the time of the
// attack and membership of the group; reading messages later from a recording would not be
// helped by it. See CVP-016, "What isn't protected".
import { ed25519 } from "@noble/curves/ed25519.js";
import { b64u, fromB64u, randomB64u, utf8, concat } from "../core/bytes.js";
import { canonicalBytes } from "../core/canonical.js";
import { SessionError, kdfChain, random, seal, open, toBytes, LABEL } from "./primitives.js";
import { MAX_SKIP, MAX_STORED } from "./session.js";

const clone = (s) => JSON.parse(JSON.stringify(s));
const header = (m) => ({ v: 1, group: m.group, id: m.id, n: m.n });
const ad = (m) => concat(utf8(`${LABEL}/group\n`), canonicalBytes(header(m)));
const signed = (m) => concat(utf8(`${LABEL}/group-sig\n`), canonicalBytes({ ...header(m), c: m.c }));

/** A new sending chain for this device in a group. Keep it secret; it's yours alone. */
export function createSenderKey(group) {
  const { secretKey, publicKey } = ed25519.keygen();
  return { group, id: randomB64u(9), ck: b64u(random(32)), n: 0, signSk: b64u(secretKey), signPk: b64u(publicKey) };
}

/** What to send each member over your one-to-one session with them (as JSON). */
export const distribution = (key) => ({ type: "sender-key", group: key.group, id: key.id, ck: key.ck, n: key.n, sign: key.signPk });

/**
 * Accept a member's sender key. `from` is the device whose one-to-one session it arrived on: the
 * session is what proves who it came from, so take it from there, never from the message.
 */
export function acceptDistribution(dist, { from }) {
  if (dist?.type !== "sender-key" || typeof dist.group !== "string" || typeof dist.id !== "string") throw new SessionError("BAD_MESSAGE", "Not a sender key");
  if (fromB64u(dist.ck).length !== 32 || fromB64u(dist.sign).length !== 32 || !Number.isSafeInteger(dist.n) || dist.n < 0) throw new SessionError("BAD_MESSAGE", "Bad sender key");
  return { group: dist.group, id: dist.id, from, ck: dist.ck, n: dist.n, sign: dist.sign, skipped: {} };
}

/** Encrypt once for the whole group. Returns { key, message }; store the new key first. */
export async function groupEncrypt(key, plaintext) {
  const k = clone(key);
  const { mk, ck } = kdfChain(fromB64u(k.ck));
  const m = { v: 1, group: k.group, id: k.id, n: k.n };
  k.ck = b64u(ck);
  k.n += 1;
  m.c = b64u(await seal(mk, toBytes(plaintext), ad(m), "group"));
  m.sig = b64u(ed25519.sign(signed(m), fromB64u(k.signSk)));
  return { key: k, message: m };
}

/** Decrypt a group message with the sender's key you accepted. Returns { state, plaintext }. */
export async function groupDecrypt(state, message) {
  const m = message;
  if (!m || m.v !== 1 || m.group !== state.group || m.id !== state.id || !Number.isSafeInteger(m.n) || m.n < 0 || typeof m.c !== "string" || typeof m.sig !== "string") {
    throw new SessionError("BAD_MESSAGE", "Not a message for this sender key");
  }
  let ok = false;
  try {
    ok = ed25519.verify(fromB64u(m.sig), signed(m), fromB64u(state.sign));
  } catch {
    ok = false;
  }
  if (!ok) throw new SessionError("UNTRUSTED", "Group message signature doesn't match its sender");
  const s = clone(state);
  let mk;
  if (s.skipped[m.n]) {
    mk = fromB64u(s.skipped[m.n]);
    delete s.skipped[m.n];
  } else {
    if (m.n < s.n) throw new SessionError("REPLAY", "Message already received");
    if (m.n - s.n > MAX_SKIP) throw new SessionError("TOO_FAR_AHEAD", "Too many messages missing");
    let ck = fromB64u(s.ck);
    while (s.n < m.n) {
      const step = kdfChain(ck);
      s.skipped[s.n] = b64u(step.mk);
      ck = step.ck;
      s.n += 1;
    }
    const step = kdfChain(ck);
    mk = step.mk;
    s.ck = b64u(step.ck);
    s.n += 1;
    const keys = Object.keys(s.skipped);
    for (let i = 0; i < keys.length - MAX_STORED; i += 1) delete s.skipped[keys[i]];
  }
  return { state: s, plaintext: await open(mk, fromB64u(m.c), ad(m), "group") };
}
