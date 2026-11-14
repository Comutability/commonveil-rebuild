# CVP-013: Private tokens (RFC 9497 VOPRF)

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.tokens` (version 1) |
| Depends on | none |
| Code | `src/tokens/voprf.js` |
| Proposed in | none (written before the proposal process; recorded in [SNIP-0004](../snips/SNIP-0004.md)) |

One-use tokens an issuer hands out without being able to recognise them later. Suite:
`P256-SHA256` in VOPRF mode (the issuer proves which key it used), from RFC 9497.

## Flow

1. The issuer publishes a public key for one scope (one vote, one month of reports, and so on).
   Keys are derived from one secret seed with `keyInfo = "secure-net/tokens/v1/<scope>"`, so a
   token for one scope is worthless in another.
2. The client makes random 32-byte inputs, blinds them and sends the blinded values (up to 64).
3. The issuer checks the client is entitled (for a vote: eligible, and not already issued), then
   evaluates them in one batch with a DLEQ proof.
4. The client checks the proof against the published key. A proof that fails means the issuer
   used a different key, which could mark whose tokens are whose: the client MUST stop.
5. A token is `{ input, output }`. Spending it, the issuer recomputes the output from the input
   and its secret key, and records the nullifier `SHA-256("secure-net/nullifier/v1\n" + input)`.
   A nullifier seen before means the token was already spent.

## What it protects, and what it doesn't

- The issuer can't link a spent token to the request it came from.
- Only the issuer can check a token. Anyone else has to trust the issuer's count.
- The issuer must keep spent nullifiers for as long as the scope's tokens are valid.
- Network addresses and timing can still link a spender to a request. Spend through something
  that hides addresses if that matters, and don't spend straight after receiving.
- A person entitled to tokens can give them to someone else. Tokens prove entitlement, not
  identity.

## Security and privacy

See "What it protects, and what it doesn't" above. In addition: forging a token needs the
discrete logarithm problem on P-256 broken, which a large quantum computer could do; that would
let an attacker make tokens, not link the ones already spent (unlinkability rests on no hardness
assumption). There is no standardised post-quantum VOPRF yet (CVP-015).

## Conformance

`test/governance.test.mjs` covers issuing, checking proofs and spending. RFC 9497's own test vectors
apply to the underlying suite (`P256-SHA256`, VOPRF mode); vectors for this part's scope
derivation and nullifiers are still to write (CVP-010, section 6).

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-12 | none | First version, in Secure Net 0.1.0 |
