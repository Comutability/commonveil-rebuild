// Private, one-use tokens from RFC 9497 VOPRF (P256-SHA256), CVP-013.
//
// An issuer gives each eligible person a few tokens without seeing them: the person sends
// "blinded" values, the issuer evaluates them with its secret key and proves (with the DLEQ proof
// RFC 9497 defines) that it used the key it published. Later, a token can be spent without the
// issuer being able to tell who it gave it to. Each token can be spent once.
//
// Used here for secret ballots (governance/vote.js): eligibility is checked when tokens are
// handed out, and the ballot itself carries only a token. Other uses: anonymous rate limits,
// anonymous reports, private invitations.
//
// Limits, stated plainly: only the issuer (who holds the secret key) can check a token, so a
// tally of secret ballots is only as honest as the issuer; the network can still reveal who sent
// what unless ballots travel through something that hides addresses; and the issuer must keep a
// list of spent tokens.
import { p256_oprf } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u, fromB64u, utf8, equalBytes, sha256B64u } from "../core/bytes.js";

const V = p256_oprf.voprf;
export const SUITE = "P256-SHA256";
const MAX_BATCH = 64;

export class TokenError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TokenError";
    this.code = code;
  }
}

/**
 * An issuer key for one purpose (scope), such as one vote. Derived from a secret seed, so the
 * issuer can keep one seed and get a separate key for every scope: a token for one vote is
 * useless in another.
 */
export function issuerKey(seed, scope) {
  const k = V.deriveKeyPair(typeof seed === "string" ? fromB64u(seed) : seed, utf8(`secure-net/tokens/v1/${scope}`));
  return { scope, secretKey: b64u(k.secretKey), publicKey: b64u(k.publicKey) };
}

/** Make n tokens to be signed. Keep `pending` private; send `request` to the issuer. */
export function requestTokens(n = 1) {
  if (!Number.isSafeInteger(n) || n < 1 || n > MAX_BATCH) throw new TokenError("BAD_COUNT", `Between 1 and ${MAX_BATCH} tokens at a time`);
  const pending = [];
  for (let i = 0; i < n; i += 1) {
    const input = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const { blind, blinded } = V.blind(input);
    pending.push({ input: b64u(input), blind: b64u(blind), blinded: b64u(blinded) });
  }
  return { pending, request: pending.map((p) => p.blinded) };
}

/** The issuer's answer to a request. Check who's asking (and how many they've had) before calling this. */
export function issueTokens(key, request) {
  if (!Array.isArray(request) || !request.length || request.length > MAX_BATCH) throw new TokenError("BAD_COUNT", `Between 1 and ${MAX_BATCH} tokens at a time`);
  try {
    const { evaluated, proof } = V.blindEvaluateBatch(fromB64u(key.secretKey), fromB64u(key.publicKey), request.map(fromB64u));
    return { evaluated: evaluated.map(b64u), proof: b64u(proof) };
  } catch {
    throw new TokenError("BAD_REQUEST", "Those aren't valid blinded values");
  }
}

/**
 * Turn the issuer's answer into tokens, checking its proof against the issuer's published key.
 * Throws if the issuer didn't use that key (which could otherwise mark whose tokens are whose).
 */
export function finishTokens(pending, response, publicKey) {
  if (!response || response.evaluated?.length !== pending.length) throw new TokenError("BAD_RESPONSE", "The issuer's answer doesn't match the request");
  let outputs;
  try {
    outputs = V.finalizeBatch(
      pending.map((p, i) => ({ input: fromB64u(p.input), blind: fromB64u(p.blind), evaluated: fromB64u(response.evaluated[i]), blinded: fromB64u(p.blinded) })),
      fromB64u(publicKey),
      fromB64u(response.proof),
    );
  } catch {
    throw new TokenError("BAD_PROOF", "The issuer's proof doesn't match its published key");
  }
  return pending.map((p, i) => ({ input: p.input, output: b64u(outputs[i]) }));
}

/** A token's spend id: the same token always gives the same id, and the id reveals nothing else. */
export const nullifier = (token) => sha256B64u(`secure-net/nullifier/v1\n${token.input}`);

/** Whether a token is one this issuer made (not whether it's been spent: see spendToken). */
export function checkToken(key, token) {
  try {
    const want = V.evaluate(fromB64u(key.secretKey), fromB64u(token.input));
    return equalBytes(want, fromB64u(token.output));
  } catch {
    return false;
  }
}

/**
 * Spend a token. spent is a Set of nullifiers (or anything with has/add). Returns the nullifier,
 * or throws if the token is forged or already spent.
 */
export function spendToken(key, token, spent) {
  if (!checkToken(key, token)) throw new TokenError("INVALID", "Not a token from this issuer");
  const id = nullifier(token);
  if (spent.has(id)) throw new TokenError("SPENT", "This token has already been used");
  spent.add(id);
  return id;
}

/** A short public fingerprint of an issuer key, to publish alongside what it's for. */
export const keyFingerprint = (publicKey) => b64u(sha256(fromB64u(publicKey))).slice(0, 22);
