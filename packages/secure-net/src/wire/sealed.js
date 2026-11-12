// The sealed relay (CVP-015): what one site sends another is encrypted from site to site and
// signed, with post-quantum algorithms alongside the classical ones.
//
// Why: messages were already end-to-end encrypted between people, but the requests carrying them
// between sites (who is writing to whom, in which conversation, when) were protected only by
// TLS. Anyone who records that traffic now could read it once TLS's key exchange is broken, and
// anything in front of a site (a CDN, a hosting platform's proxy) could read it today. Sealed,
// only the two sites can.
//
//   Encryption: an ephemeral P-256 ECDH and ML-KEM-768 (FIPS 203), both shared secrets through
//     HKDF-SHA-256, then AES-256-GCM. Breaking it needs both to be broken.
//   Signatures: ML-DSA-65 (FIPS 204), in addition to the site's Ed25519 signature. A request
//     counts only if both verify.
//   Replies: sealed with a one-time AES-256 key that travels inside the sealed request.
//
// This file imports nothing, so it runs anywhere with Web Crypto: give it the two post-quantum
// algorithms from @noble/post-quantum (ml_kem768, ml_dsa65).

export const SUITE = "p256-mlkem768+mldsa65";
const INFO = "secure-net/relay/v1";

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
export const b64u = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const fromB64u = (s) => {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new RelayError("MALFORMED", "Not base64url");
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

export class RelayError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "RelayError";
    this.code = code;
  }
}

/** The context a sealed request is bound to: it only opens as this request, between these sites. */
export const relayContext = ({ from, to, path }) => `${from}\n${to}\n${path}`;

/**
 * The relay's algorithms. ml_kem768 and ml_dsa65 are @noble/post-quantum's (or anything with the
 * same keygen / encapsulate / decapsulate and keygen / sign / verify).
 */
export function relaySuite({ ml_kem768, ml_dsa65, subtle = globalThis.crypto.subtle, random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) }) {
  const ECDH = { name: "ECDH", namedCurve: "P-256" };
  let expanded = { seed: "", key: null };

  async function aesKey(ecdhShared, kemShared, context, transcript) {
    const ikm = await subtle.importKey("raw", concat(ecdhShared, kemShared), "HKDF", false, ["deriveKey"]);
    const salt = new Uint8Array(await subtle.digest("SHA-256", enc(context)));
    // The key is tied to this exact exchange: both public halves, by their hash.
    const bound = new Uint8Array(await subtle.digest("SHA-256", transcript));
    return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: concat(enc(INFO), bound) }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  async function gcm(mode, key, iv, data, context) {
    try {
      return new Uint8Array(await subtle[mode]({ name: "AES-GCM", iv, additionalData: enc(context) }, key, data));
    } catch {
      throw new RelayError("CANNOT_OPEN", "That couldn't be opened: it wasn't sealed for this site and this request.");
    }
  }

  return {
    suite: SUITE,

    /** A site's relay keys. Publish kem.public and sig.public in the site document; keep the secrets. */
    async generateKeys() {
      const ec = await subtle.generateKey(ECDH, true, ["deriveBits"]);
      const ecPub = new Uint8Array(await subtle.exportKey("raw", ec.publicKey));
      const ecSecret = new Uint8Array(await subtle.exportKey("pkcs8", ec.privateKey));
      const kem = ml_kem768.keygen(random(64));
      const sigSeed = random(32);
      return {
        kem: { public: `${b64u(ecPub)}.${b64u(kem.publicKey)}`, secret: `${b64u(ecSecret)}.${b64u(kem.secretKey)}` },
        sig: { public: b64u(ml_dsa65.keygen(sigSeed).publicKey), secret: b64u(sigSeed) },
      };
    },

    /** Seal text for a site. Answers { sealed, replyKey }: keep replyKey to open the reply. */
    async seal(recipientKemPublic, text, context) {
      const [ecPubB, kemPubB] = String(recipientKemPublic).split(".");
      let theirEc;
      let kem;
      try {
        theirEc = await subtle.importKey("raw", fromB64u(ecPubB), ECDH, false, []);
        kem = ml_kem768.encapsulate(fromB64u(kemPubB));
      } catch {
        throw new RelayError("BAD_KEY", "That site's relay key isn't usable.");
      }
      const eph = await subtle.generateKey(ECDH, true, ["deriveBits"]);
      const ephPub = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
      const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: theirEc }, eph.privateKey, 256));
      const key = await aesKey(shared, kem.sharedSecret, context, concat(ephPub, kem.cipherText));
      const replyKey = random(32);
      const iv = random(12);
      const ct = await gcm("encrypt", key, iv, enc(JSON.stringify({ r: b64u(replyKey), t: text })), context);
      return { sealed: JSON.stringify({ v: 1, s: SUITE, e: b64u(ephPub), k: b64u(kem.cipherText), n: b64u(iv), c: b64u(ct) }), replyKey };
    },

    /** Open something sealed for this site. Answers { text, replyKey }. */
    async open(kemSecret, sealed, context) {
      let box;
      try {
        box = JSON.parse(sealed);
      } catch {
        box = null;
      }
      if (!box || box.v !== 1 || box.s !== SUITE) throw new RelayError("MALFORMED", "Not a sealed request this site understands.");
      const [ecSecretB, kemSecretB] = String(kemSecret).split(".");
      const ephPub = fromB64u(box.e);
      const kemCt = fromB64u(box.k);
      let shared;
      let kemShared;
      try {
        const mine = await subtle.importKey("pkcs8", fromB64u(ecSecretB), ECDH, false, ["deriveBits"]);
        const theirs = await subtle.importKey("raw", ephPub, ECDH, false, []);
        shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: theirs }, mine, 256));
        kemShared = ml_kem768.decapsulate(kemCt, fromB64u(kemSecretB));
      } catch {
        throw new RelayError("CANNOT_OPEN", "That couldn't be opened: it wasn't sealed for this site and this request.");
      }
      const key = await aesKey(shared, kemShared, context, concat(ephPub, kemCt));
      const inner = JSON.parse(dec(await gcm("decrypt", key, fromB64u(box.n), fromB64u(box.c), context)));
      return { text: String(inner.t), replyKey: fromB64u(inner.r) };
    },

    /** Seal a reply with the key that came inside the request. */
    async sealReply(replyKey, text, context) {
      const key = await subtle.importKey("raw", replyKey, "AES-GCM", false, ["encrypt"]);
      const iv = random(12);
      return JSON.stringify({ v: 1, n: b64u(iv), c: b64u(await gcm("encrypt", key, iv, enc(text), `reply\n${context}`)) });
    },

    async openReply(replyKey, sealed, context) {
      let box;
      try {
        box = JSON.parse(sealed);
      } catch {
        box = null;
      }
      if (!box || box.v !== 1) throw new RelayError("MALFORMED", "Not a sealed reply.");
      const key = await subtle.importKey("raw", replyKey, "AES-GCM", false, ["decrypt"]);
      return dec(await gcm("decrypt", key, fromB64u(box.n), fromB64u(box.c), `reply\n${context}`));
    },

    /** The post-quantum signature over a request's signature base (wire/federation.js signatureBase). */
    sign(sigSecret, text) {
      // The signing key is expanded from its seed once, not for every request.
      if (expanded.seed !== sigSecret) expanded = { seed: sigSecret, key: ml_dsa65.keygen(fromB64u(sigSecret)).secretKey };
      return b64u(ml_dsa65.sign(enc(text), expanded.key));
    },

    verify(sigPublic, text, signature) {
      try {
        return ml_dsa65.verify(fromB64u(signature), enc(text), fromB64u(sigPublic));
      } catch {
        return false;
      }
    },
  };
}

/**
 * What a site says about its relay keys in its site document, checked. Answers
 * { suite, kem, sig } or null if it publishes none (or a suite this version doesn't speak).
 */
export function relayKeysOf(doc) {
  const pq = doc && doc.pq;
  if (!pq || pq.suite !== SUITE || typeof pq.kem !== "string" || typeof pq.sig !== "string") return null;
  if (!/^[A-Za-z0-9_-]{80,100}\.[A-Za-z0-9_-]{1500,1700}$/.test(pq.kem) || !/^[A-Za-z0-9_-]{2500,2700}$/.test(pq.sig)) return null;
  return { suite: pq.suite, kem: pq.kem, sig: pq.sig };
}

/**
 * Whether a site's published relay keys are acceptable given what was pinned before: the same
 * as before, or new where there were none. Never fewer: a site that has sealed can't go back.
 */
export function relayKeysAcceptable(pinned, now) {
  if (!pinned) return true;
  return Boolean(now) && pinned.kem === now.kem && pinned.sig === now.sig;
}
