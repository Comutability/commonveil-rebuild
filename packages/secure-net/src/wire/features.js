// Feature negotiation (CVP-008): each site publishes what it speaks, and two sites use what both
// support. Unknown features are ignored, never errors, so sites can upgrade one at a time.
export const SECURE_NET_VERSION = "0.1.0";

/** Everything this version of Secure Net implements, with the version of each. */
export const FEATURES = {
  "cvp.federation": 1, // signed site-to-site requests (wire/federation.js)
  "cvp.identity": 2, // account key chains with post-quantum keys (crypto/identity.js)
  "cvp.envelope": 1, // end-to-end message envelopes (crypto/envelope.js)
  "cvp.commons-ledger": 1, // replicated community ledger and failover (commons/ledger.js)
  "cvp.governance": 1, // motions, debates, public and secret ballots (governance/)
  "cvp.tokens": 1, // RFC 9497 VOPRF tokens (tokens/voprf.js)
  "cvp.personas": 1, // personas and migration notices (identity/portable.js)
  "cvp.consent": 1, // consent capsules (consent/capsule.js)
  "cvp.extensions": 1, // extension manifests and themes (extensions/manifest.js)
};

/** What a site publishes about itself (in its /.well-known/commonveil document). */
export const describeSite = (features = FEATURES) => ({ protocol: "secure-net", version: SECURE_NET_VERSION, features });

/** The features two sites share, at the lower of their two versions. */
export function negotiate(ours, theirs) {
  const out = {};
  for (const [name, v] of Object.entries(ours || {})) {
    const t = theirs?.[name];
    if (Number.isSafeInteger(v) && Number.isSafeInteger(t) && t > 0) out[name] = Math.min(v, t);
  }
  return out;
}
