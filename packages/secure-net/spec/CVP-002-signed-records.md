# CVP-002: Canonical encoding and signed records

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | none (every implementation needs it); quantum-resistant keys are announced as `cvp.pq-signatures` (CVP-015) |
| Depends on | nothing |
| Code | `src/core/canonical.js`, `src/core/signed.js`, `src/core/bytes.js` |
| Proposed in | Written down in [SNIP-0004](../snips/SNIP-0004.md) from the code as released in 0.4.0; the quantum-resistant keys came from SNIP-0002 |

## Summary

One way to turn a JSON value into bytes, and one envelope for everything that is signed: ledger
blocks, motions, ballots, device lists, prekeys, consent capsules, manifests. Every other part
that signs anything builds on this one, so it is the first thing a new implementation needs.

## Definitions

- **base64url**: RFC 4648 section 5, without padding. Receivers MUST refuse other characters.
- **Canonical JSON**: the encoding in section 1.
- **Kind**: a record type name, registered in the registry (CVP-000, section 7), matching
  `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`.
- **Public key string**: for an Ed25519 key, the base64url of its 32 bytes. For a
  quantum-resistant key, the Ed25519 string, a full stop, and the base64url of the ML-DSA-65
  public key (1,952 bytes).

## Specification

### 1. Canonical JSON

The canonical form of a value is:

- `null`, `true`, `false` as those words;
- an integer `n` with `-(2^53 - 1) <= n <= 2^53 - 1`, in decimal, with no leading zeros, no plus
  sign and no fraction or exponent; negative zero is `0`;
- a string in double quotes, escaping only `"` as `\"`, `\` as `\\` and the characters U+0000 to
  U+001F (as `\b`, `\t`, `\n`, `\f`, `\r` where those exist, otherwise `\u00xx` in lower-case hex);
  every other character, including U+2028, U+2029 and everything outside ASCII, is written as
  itself in UTF-8;
- an array as `[`, its elements' canonical forms separated by `,`, then `]`;
- an object as `{`, its members as `"key":value` separated by `,`, then `}`, with members **sorted
  by their keys compared as sequences of UTF-16 code units** (as RFC 8785 does), and members whose
  value is absent left out.

There is no whitespace anywhere outside strings. The canonical bytes are the UTF-8 of the
canonical form.

An encoder MUST refuse (not normalise) any value with more than one possible encoding or none:
fractions, numbers outside the safe range, strings containing a lone surrogate, and anything that
isn't one of the types above. To carry a fraction, use two integers or a string.

This is the subset of RFC 8785 (JCS) whose output is the same in every language, which is why
numbers are restricted.

### 2. Key ids

A key's id (`kid`) is the first 22 characters of the base64url of the SHA-256 of:

- for an Ed25519 key, its 32 public-key bytes;
- for a quantum-resistant key, the UTF-8 bytes of its public key string (both halves and the full
  stop).

So the id names both halves, and the same Ed25519 key used alone and in a quantum-resistant key
has two different ids.

### 3. Signed records

A signed record is a JSON object:

```
{ "kind": <kind>, "body": <any JSON object>, "sig": <signature>, "cosigs": [<signature>, ...]? }
```

and a signature is

```
{ "kid": <signer's key id>, "alg": "Ed25519" | "Ed25519+ML-DSA-65", "value": <base64url>, "pq": <base64url>? }
```

The **signed bytes** are the UTF-8 of `secure-net/<kind>/v1`, the byte `0x0a`, then the canonical
bytes of the body. Including the kind means a signature for one kind of record can never be
replayed as another.

- With an Ed25519 key, `alg` is `Ed25519` and `value` is the Ed25519 signature (RFC 8032) of the
  signed bytes.
- With a quantum-resistant key, `alg` is `Ed25519+ML-DSA-65`, `value` is the Ed25519 signature and
  `pq` is the ML-DSA-65 signature (FIPS 204 `ML-DSA.Sign`, empty context) of the same signed
  bytes. Signers MAY use hedged (randomised) ML-DSA signing.

`cosigs`, where a part allows it, are further signatures over the same signed bytes by other keys.

### 4. Verifying

A receiver verifies a record against a public key it already trusts for that purpose (the parts
say which). It MUST refuse the record unless all of these hold:

1. `kind` is one the receiver expected in this place;
2. the key's id equals `sig.kid`;
3. the **key** decides the algorithm: an Ed25519 key needs `alg` `Ed25519`; a quantum-resistant
   key needs `alg` `Ed25519+ML-DSA-65` **and both** signatures to verify. A record signed with
   only the Ed25519 half of a quantum-resistant key is refused, so stripping the ML-DSA-65
   signature can't downgrade a record;
4. every signature verifies over the signed bytes computed from the record as received.

Receivers MUST compute the signed bytes from the body as received, keep unknown body members when
storing or forwarding, and not act on members they don't understand (CVP-000, 5.1).

### 5. Record ids

A record's id is the base64url SHA-256 of the canonical JSON of `{ kind, body, sig, cosigs }`
(with `cosigs` left out when absent). Two copies of a record with different signatures (hedged
ML-DSA signing, or added cosignatures) therefore have different ids; parts that need a stable id
for the content say how to compute it.

## Security and privacy

- **What it protects.** Integrity and authorship of records, against anyone who doesn't hold the
  signing key, including sites and relays that store or forward them. With a quantum-resistant key,
  forging needs both Ed25519 and ML-DSA-65 broken.
- **What it doesn't.** Signatures aren't encryption: bodies are readable by whoever holds the
  record. A signature proves which key signed, not which person: binding keys to people is up to
  the parts that use this one (device lists, safety numbers, ledger keys). A record can be
  replayed in the same place unless the part that uses it says how to refuse repeats (sequence
  numbers, nonces, expiry). Ed25519-only records could be forged by an attacker with a large
  quantum computer at the time of the attack; quantum-resistant keys exist for that reason.
- Canonical JSON leaks nothing extra, but the ordering of keys is fixed, so the size of a body is
  visible to anyone who sees the record.

## Conformance

An implementation conforms to this part if it passes `spec/vectors/cvp-002-v1.json`:

- for every `canonical` case, encoding the parsed `json` gives exactly `canonical`;
- every `refused` case is refused;
- `signingBytes`, both records and both record ids are reproduced (the ML-DSA-65 signature by
  verifying it, since signing may be hedged);
- every `mustRefuse` record is refused.

The canonical cases have been checked against a separate implementation (Python, written from
this section), and the Ed25519 signature and key ids against Node's built-in crypto.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-13 | SNIP-0004 | First written down, describing the behaviour of Secure Net 0.4.0, unchanged since quantum-resistant keys were added (SNIP-0002) |
