# Private, end-to-end encrypted, and interoperable

How sites run by different people talk to each other without any of them being able to read
messages or pretend to be someone, and what each one still learns.

## The three rules that make it work

1. **Keys say who people are; sites only carry.** Every account has a chain of key statements,
   each signed by the one before (CVP-001). Every device is certified by the account key. Every
   message is signed by the sending device and sealed to each recipient device. People's apps
   check all of it. A site that lies about someone's keys is caught by the chain check and by
   pinning (a changed key that doesn't chain shows as a warning, with a safety number to compare).
2. **Sites prove which site they are.** Each site has an Ed25519 key published at
   `/.well-known/commonveil`. Every request between sites is signed over its method, both sites,
   path, time, a one-off nonce, a digest of the body and the person it's for (CVP-005). Requests
   more than five minutes off, or with a nonce seen before, are refused.
3. **Only shared formats, never shared trust.** Two sites agree on byte-exact encodings
   (CVP-002) and on which features both speak (`wire/features`). Neither has to trust the
   other's database, software or operator.

## A message from Ann (on a.example) to Ben (on b.example)

1. Ann's app looks up `ben.b.example`. Her site, a.example, asks b.example (signed request) for
   Ben's key chain and devices, and passes them back. Ann's app checks the chain itself.
2. Ann's app seals the message to each of Ben's devices (and her own), signs it, and gives the
   ciphertext to a.example.
3. a.example relays it to b.example, signed with a.example's site key, on Ann's behalf.
4. b.example checks the site signature, stores the ciphertext, and delivers it to Ben's devices,
   which check Ann's signature and open it.

Neither site can read it. Either can refuse or delay it, and both learn that Ann and Ben talked,
when, and roughly how much.

## Communities across sites

A community lives on its home site; people from other sites join through their own site, which
relays for them. With the Commons ledger (CVP-011), approved sites keep a checked copy of the
community and can serve it if the home site goes down, without being able to read content or
change who's in charge.

## What each party learns

| | Content | Who talks to whom | Community membership | Network address |
| --- | --- | --- | --- | --- |
| Your own site | No | Yes, for your conversations | Yours | Yes |
| The other person's site | No | Yes, for conversations with its people | Of communities it hosts | Your site's, not yours |
| A community's home or replica | No | Who posts in it, and when | Yes | Of the sites relaying |
| Someone watching the network | No | Which sites talk | No | Yes |

Clients must show this (the "Privacy Lens"), and must not promise more.

## Running a compatible site

Any software that implements CVP-001, 002 and 005 can talk to Commonveil sites. With this
library, that's the `crypto`, `core` and `wire` modules plus HTTP routes for the endpoints in
the site document. Commonveil's self-hosted server (`server/federation` in Commonveil) is the
reference.
