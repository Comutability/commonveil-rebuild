// One-to-one sessions between two devices (CVP-016): a hybrid post-quantum handshake, then a
// double ratchet that mixes a fresh ML-KEM-768 secret into every DH ratchet step.
//
// State is plain JSON and every call returns a new state rather than changing the one given, so
// a message that fails to decrypt leaves the session exactly as it was. Store the returned state
// before showing the message, and never use an older copy again (that would reuse keys).
import { b64u, fromB64u, sha256B64u } from "../core/bytes.js";
import { canonicalBytes } from "../core/canonical.js";
import { concat } from "../core/bytes.js";
import { verifyBundle, verifyDeviceList } from "./keys.js";
import {
  SessionError, dh, dhKeyPair, kemKeyPair, encapsulate, decapsulate,
  handshakeSecret, kdfRoot, kdfChain, transcriptHash, seal, open, toBytes,
} from "./primitives.js";

export const VERSION = 1;
/** How far ahead of the last message a message may be, in one chain. */
export const MAX_SKIP = 1000;
/** How many keys for not-yet-arrived messages a session keeps, across chains. */
export const MAX_STORED = 2000;

const clone = (s) => JSON.parse(JSON.stringify(s));
const B64U = /^[A-Za-z0-9_-]+$/;
const isKey32 = (k) => {
  try {
    return typeof k === "string" && B64U.test(k) && fromB64u(k).length === 32;
  } catch {
    return false;
  }
};

function transcript(initiator, responder, x) {
  return {
    v: VERSION,
    initiator,
    responder,
    ek: x.ek,
    ct: sha256B64u(fromB64u(x.ct)),
    signed: x.signed,
    pq: x.pq,
    oneTime: x.oneTime ?? null,
  };
}

const party = (account, dev) => ({ account, device: dev.kid, sign: dev.sign, dh: dev.dh });

function newState({ rk, ad, peer, self }) {
  return { v: VERSION, ad, rk: b64u(rk), peer, self, dhs: null, dhr: null, kems: null, kemr: null, sendCt: null, cks: null, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, pending: null };
}

/**
 * Start a session with one of someone's devices, from a bundle their site handed out.
 *   me: { device, deviceList }   your device (with secrets) and your account's signed device list
 *   accountKey                    the account key you trust for them (pinned; see safetyNumber)
 *   minSeq                        the highest device-list seq you've seen for them
 * Returns the session state. Encrypt straight away; the first messages carry the handshake.
 */
export function initiate({ me, bundle, accountKey, minSeq = 0, now = Date.now() }) {
  const v = verifyBundle(bundle, { accountKey, minSeq, now });
  const myAccount = me.deviceList.body.account;
  const myDev = me.deviceList.body.devices.find((d) => d.kid === me.device.kid);
  if (!myDev || myDev.dh !== me.device.dh.pk) throw new SessionError("BAD_INPUT", "Your device isn't on your own device list");

  const ek = dhKeyPair();
  const enc = encapsulate(v.pq.pub);
  const dhs = [dh(me.device.dh.sk, v.signed.pub), dh(ek.sk, v.device.dh), dh(ek.sk, v.signed.pub)];
  if (v.oneTime) dhs.push(dh(ek.sk, v.oneTime.pub));
  const x = { list: me.deviceList, device: me.device.kid, ek: ek.pk, ct: enc.ct, signed: v.signed.id, pq: v.pq.id, oneTime: v.oneTime?.id ?? null };
  const th = transcriptHash(transcript(party(myAccount, myDev), party(accountKey, v.device), x));

  const s = newState({ rk: handshakeSecret(dhs, enc.ss, th), ad: b64u(th), peer: { account: accountKey, device: v.device.kid }, self: me.device.kid });
  s.dhs = dhKeyPair();
  s.dhr = v.signed.pub;
  s.kems = kemKeyPair();
  const step = kdfRoot(fromB64u(s.rk), dh(s.dhs.sk, s.dhr));
  s.rk = b64u(step.rk);
  s.cks = b64u(step.ck);
  s.pending = x;
  return s;
}

/** Who a first message claims to be from, so you can look up (or ask about) their account key. */
export function initialSender(message) {
  const x = message?.x;
  if (!x?.list?.body) return null;
  return { account: x.list.body.account, device: x.device, handshake: handshakeId(message) };
}

/** An id for a first message's handshake. Remember these while a signed prekey is live and refuse repeats. */
export const handshakeId = (message) => (message?.x?.ek ? sha256B64u(fromB64u(message.x.ek)).slice(0, 22) : null);

/** Whether a message starts a new session (rather than continuing one you have). */
export const isInitial = (message) => Boolean(message?.x);

/**
 * Accept a first message on the device it was sent to.
 *   me: { device, deviceList, prekeys }  prekeys are the device's prekey secrets (id -> secret)
 *   accountKey                          the account key you trust for the sender
 * Returns { state, plaintext, prekeys }: prekeys without the one-time prekeys this used. Store
 * both before showing the message; a one-time prekey must never be used twice.
 */
export async function respond({ me, message, accountKey, minSeq = 0 }) {
  const x = message?.x;
  if (!x || typeof x !== "object") throw new SessionError("BAD_MESSAGE", "Not a first message");
  if (!isKey32(x.ek)) throw new SessionError("BAD_MESSAGE", "Bad ephemeral key");
  const list = verifyDeviceList(x.list, { accountKey, minSeq });
  const theirDev = list.devices.find((d) => d.kid === x.device);
  if (!theirDev) throw new SessionError("UNTRUSTED", "The sending device isn't on its account's device list");
  const myDev = me.deviceList.body.devices.find((d) => d.kid === me.device.kid);
  if (!myDev) throw new SessionError("BAD_INPUT", "Your device isn't on your own device list");

  const secret = (id, type, want) => {
    const k = id == null ? null : me.prekeys[id];
    if (!k || k.type !== type || (want === "oneTime" && !k.oneTime) || (want === "signed" && (k.oneTime || k.lastResort))) {
      throw new SessionError("UNKNOWN_PREKEY", "That prekey is unknown or already used");
    }
    return k;
  };
  const spk = secret(x.signed, "x25519", "signed");
  const pq = secret(x.pq, "ml-kem-768", "pq");
  if (!pq.oneTime && !pq.lastResort) throw new SessionError("UNKNOWN_PREKEY", "That prekey is unknown or already used");
  const opk = x.oneTime == null ? null : secret(x.oneTime, "x25519", "oneTime");

  const dhs = [dh(spk.sk, theirDev.dh), dh(me.device.dh.sk, x.ek), dh(spk.sk, x.ek)];
  if (opk) dhs.push(dh(opk.sk, x.ek));
  const ss = decapsulate(x.ct, pq.sk);
  const th = transcriptHash(transcript(party(list.account, theirDev), party(me.deviceList.body.account, myDev), x));

  const s = newState({ rk: handshakeSecret(dhs, ss, th), ad: b64u(th), peer: { account: list.account, device: theirDev.kid }, self: me.device.kid });
  s.dhs = { sk: spk.sk, pk: spk.pk };
  const out = await decrypt(s, message);
  const prekeys = { ...me.prekeys };
  if (opk) delete prekeys[x.oneTime];
  if (pq.oneTime) delete prekeys[x.pq];
  return { ...out, prekeys };
}

const adOf = (s, h, x) => concat(fromB64u(s.ad), canonicalBytes(x ? { h, x } : { h }));

/** Encrypt for the peer. Returns { state, message }; message is JSON for the relay. */
export async function encrypt(state, plaintext) {
  if (!state?.cks) throw new SessionError("NOT_READY", "This session can't send until it has received a message");
  const s = clone(state);
  const { mk, ck } = kdfChain(fromB64u(s.cks));
  s.cks = b64u(ck);
  const h = { dh: s.dhs.pk, kem: s.kems.pk, pn: s.pn, n: s.ns };
  if (s.sendCt) h.ct = s.sendCt;
  s.ns += 1;
  const message = { v: VERSION, h };
  if (s.pending) message.x = s.pending;
  message.c = b64u(await seal(mk, toBytes(plaintext), adOf(s, h, message.x)));
  return { state: s, message };
}

function checkHeader(message) {
  if (!message || message.v !== VERSION) throw new SessionError("BAD_MESSAGE", "Unsupported message version");
  const h = message.h;
  if (!h || !isKey32(h.dh) || typeof h.kem !== "string" || !B64U.test(h.kem)) throw new SessionError("BAD_MESSAGE", "Bad message header");
  if (!Number.isSafeInteger(h.n) || h.n < 0 || !Number.isSafeInteger(h.pn) || h.pn < 0) throw new SessionError("BAD_MESSAGE", "Bad message counters");
  if (h.ct != null && (typeof h.ct !== "string" || !B64U.test(h.ct))) throw new SessionError("BAD_MESSAGE", "Bad KEM ciphertext");
  if (typeof message.c !== "string" || !B64U.test(message.c)) throw new SessionError("BAD_MESSAGE", "Bad ciphertext");
}

function skipTo(s, until) {
  if (!s.ckr) return;
  if (until - s.nr > MAX_SKIP) throw new SessionError("TOO_FAR_AHEAD", "Too many messages missing");
  let ck = fromB64u(s.ckr);
  while (s.nr < until) {
    const step = kdfChain(ck);
    s.skipped[`${s.dhr}:${s.nr}`] = b64u(step.mk);
    ck = step.ck;
    s.nr += 1;
  }
  s.ckr = b64u(ck);
  const keys = Object.keys(s.skipped);
  for (let i = 0; i < keys.length - MAX_STORED; i += 1) delete s.skipped[keys[i]];
}

function ratchet(s, h) {
  // Once we've sent an ML-KEM key, every new chain from the peer must answer it: no ciphertext
  // means someone is trying to step the session down to classical-only, so refuse.
  if (s.kems && !h.ct) throw new SessionError("DOWNGRADE", "Message is missing its ML-KEM ciphertext");
  if (!s.kems && h.ct) throw new SessionError("BAD_MESSAGE", "Unexpected ML-KEM ciphertext");
  const ss = h.ct ? decapsulate(h.ct, s.kems.sk) : new Uint8Array(0);
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = h.dh;
  s.kemr = h.kem;
  let step = kdfRoot(fromB64u(s.rk), dh(s.dhs.sk, s.dhr), ss);
  s.ckr = b64u(step.ck);
  s.dhs = dhKeyPair();
  s.kems = kemKeyPair();
  const enc = encapsulate(s.kemr);
  s.sendCt = enc.ct;
  step = kdfRoot(step.rk, dh(s.dhs.sk, s.dhr), enc.ss);
  s.rk = b64u(step.rk);
  s.cks = b64u(step.ck);
}

/** Decrypt a message from the peer. Returns { state, plaintext } (plaintext is bytes). */
export async function decrypt(state, message) {
  checkHeader(message);
  const s = clone(state);
  const h = message.h;
  const ad = adOf(s, h, message.x);
  let c;
  try {
    c = fromB64u(message.c);
  } catch {
    throw new SessionError("BAD_MESSAGE", "Bad ciphertext");
  }
  const id = `${h.dh}:${h.n}`;
  let mk;
  if (s.skipped[id]) {
    mk = fromB64u(s.skipped[id]);
    delete s.skipped[id];
  } else {
    if (h.dh !== s.dhr) {
      skipTo(s, h.pn);
      ratchet(s, h);
    }
    skipTo(s, h.n);
    if (h.n < s.nr) throw new SessionError("REPLAY", "Message already received");
    const step = kdfChain(fromB64u(s.ckr));
    mk = step.mk;
    s.ckr = b64u(step.ck);
    s.nr += 1;
  }
  const plaintext = await open(mk, c, ad);
  // Hearing back means the peer has the session, so stop sending the handshake.
  if (s.pending && !message.x) s.pending = null;
  return { state: s, plaintext };
}

// ---- Several devices (CVP-016, "Devices") ----

/**
 * What to do to send to everyone on a verified device list: which devices already have a
 * session, which need a bundle fetched, and which sessions to drop because the device is gone.
 * Leave out your own device (skip) but include your account's other devices.
 */
export function planFanOut(list, sessions, { skip } = {}) {
  const want = new Set(list.devices.map((d) => d.kid).filter((k) => k !== skip));
  const have = Object.keys(sessions || {});
  return {
    encryptTo: [...want].filter((k) => have.includes(k)),
    needBundles: [...want].filter((k) => !have.includes(k)),
    drop: have.filter((k) => !want.has(k)),
  };
}

/** Encrypt the same plaintext for several devices. Returns { sessions, messages } keyed by device. */
export async function encryptToDevices(sessions, plaintext) {
  const out = { sessions: { ...sessions }, messages: {} };
  for (const [kid, state] of Object.entries(sessions)) {
    const r = await encrypt(state, plaintext);
    out.sessions[kid] = r.state;
    out.messages[kid] = r.message;
  }
  return out;
}
