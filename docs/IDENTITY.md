# Commonveil Identity

How accounts work on a self-hosted Commonveil site: signing in, passkeys, confirming new devices,
and getting an account back. `server/auth.mjs` is the server side, `src/lib/identity/` and
`src/lib/crypto/owner.js` the app side, and `tests/identity.test.mjs` tests every path, including
passkeys with a software authenticator.

(On the hosted site, commonveil.online, sign-in is still by email, because Base44 runs it. Everything
below is for self-hosted sites.)

## In short

| | What it is | What it's for |
| --- | --- | --- |
| **Username and password** | Your account's name (also your address on other sites) and a password of at least 10 characters. | Signing in. |
| **Passkey** | A key kept by your device, or synced by a password manager. Unlocked with your fingerprint, face or device PIN. | Signing in without a password, confirming a new device, getting back in. |
| **Recovery phrase** | 24 words, made when you set up encryption. Mandatory. | Unlocking your messages on a new device, confirming a new device, getting back in. |
| **Private key** | The same secret as the phrase, written as one string (`cvkey1…`). | The same as the phrase. Keep whichever is easier to store. |
| **Another device** | A browser already signed in to your account. | Approving a new device. |

There's no email. Nobody, including the site's admin, can get you back into your account if you lose
your password and all of these.

## Ownership: the owner key

Like a Nostr account, a Commonveil account is owned by a key, not by an email address.

The recovery phrase is 256 bits of entropy (BIP-39). The **private key** is the same 256 bits with
a 4-byte SHA-256 checksum, base64url, after `cvkey1`. From the entropy, the app derives:

- the **recovery keys** that unlock your encrypted keyring backup (`docs/PROTOCOL.md`), and
- the **owner key**: Ed25519, seeded by `HKDF-SHA-256(entropy, salt "commonveil/owner/v1", info "ed25519")`.

The site stores only the owner key's public half. To prove the account is yours, the app signs
the site's one-time challenge:

```
commonveil-owner/v1
<site host>
<purpose: set-owner | verify-device | recover>
<challenge>
```

The site name and the purpose are part of what's signed, so a signature can't be replayed on
another site or for another purpose. The phrase and the private key never leave your device: only
the signature is sent.

The app records the owner key whenever the phrase is to hand: when you set up encryption, when you
change your phrase, and when you use it to unlock your messages on a new device. You can also
enter it in **Settings → Sign-in and recovery**.

## Encrypted identity archive (experimental)

Commonveil has an **Identity and portable archive** screen in Settings. It makes a signed,
encrypted backup of the **messages currently readable on the exporting device** and the
contacts inferred from those conversations. This is an early, file-only backup and
read-only viewer, **not an account migration**.

- The archive is signed with both Ed25519 and ML-DSA-65 using keys derived from the existing
  24-word recovery secret. This is a hybrid post-quantum **file signature**, not an upgrade to
  the site's account login or a new, live CVP-017 actor identity. Its public signing key and
  some metadata, including the site address and counts, remain visible in the file.
- Contacts and message history are encrypted locally using AES-256-GCM. Both encrypted parts
  have hashes in the signed manifest. Only an authorised browser with the matching phrase
  can decrypt them, subject to trusting the application's JavaScript delivery.
- Import checks the hybrid signatures and encrypted part digests and can show the archive in
  a read-only viewer. It does not log the user into a new account, restore message routing,
  create live DMs, change memberships, migrate attachments, or make old messages readable
  on a device that never held their required keys.
- When a user chooses to keep a copy in browser storage, **only the encrypted file** is saved.
  The decrypted preview stays in memory for that Settings screen. Earlier experimental
  plaintext archives stored by this browser are discarded on opening the screen.
- This file does **not** include a zero-knowledge proof system. Signing a challenge with the
  owner's private key proves key possession, but it is not the same thing as a general
  zero-knowledge proof. The original site still controls a site-specific login, and its
  administrators could serve malicious JavaScript, or deny service.

The secure, genuinely portable account move, signed destination proof, authenticated archive
streaming, inbox/outbox relay cutover and new-device history transfer are proposed in
[Secure Net SNIP-0007](https://github.com/Comutability/secure-net/pull/16).
These remain to be specified, implemented, tested between independent instances and reviewed.
Secure Net stays an independent protocol; Commonveil is one application that can use it.

## Protocol actors: one identity, not one issuer

The app's own sign-in is one thing; a **Secure Net actor** (CVP-017) is another. An actor is a
quantum-resistant account key, a document signed by that key saying what it's called and which
devices speak for it, and a handle. Its id *is* the key's id, so a site can serve the document but
can't change who it names.

Secure Net is a transport between sites: an inbox, an outbox, a relay. It does not issue
identities. Anyone can make a CVP-017 actor with any compatible application, offline, and this
app's actor is simply the one Commonveil made for them. **Settings → Protocol identity** shows this
account's actor — handle, actor id, fingerprint, key type, devices, `seq`, and whether it verifies —
and the check runs in the browser against `packages/secure-net`'s own rules, not on a site's word.

The same screen checks an **actor document made elsewhere**: paste it or choose the file. The hybrid
signature must verify, the id must be the account key's id, the device list inside must be signed by
that key, and its `seq` must not be older than one this browser already accepted (the highest seen
is remembered per actor, and only ever goes up). The file is read locally: nothing is uploaded, and
nothing is saved to the account. A document that verifies proves a key exists and signed that
version. It does **not** prove that the signed-in account owns that actor.

### Why an outside actor can't be attached to an account yet

Attaching one would need both of these, and neither is built:

1. a fresh, single-use challenge from this site's server that the outside actor's own hybrid key
   signs — so a copied document is useless and an old answer can't be replayed; and
2. a signature from one of this account's **currently certified devices** over that same challenge —
   so nobody can attach someone else's actor to a stranger's account,

with replay protection tested end to end, and cross-instance tests before any live routing depends
on it. Until then the screen only reads: there is no code path that binds an actor, and no document
is accepted as proof of ownership. Leaving it unbuilt is deliberate; a half-tested binding would be
worse than none.

### Preparing a move, without pretending it happened

The migration checklist asks a destination one public question — its site document — and lists what
it says it can do: the protocol it speaks, whether the document is for that address, whether it
publishes a site key and relay endpoints, whether it serves actor documents at all, and whether it
seals relay traffic. The address guard is the strict one: HTTPS only, public names only (no numeric,
loopback, private or reserved addresses), no credentials, redirects refused, and the reply capped.

The checklist blocks any claimed readiness when post-quantum relay keys, required versioned
Secure Net transfer capabilities, or independent mailbox and outbox endpoints are missing.
Advertised support alone is not proof that real transfer or import works.

It is preparation. Moving an account or an actor, copying history, deleting anything at the old site
and switching over are **not** implemented, and the screen says so rather than implying them.
Nothing about the account, its keys or its messages is sent to the destination.

## Signing in

- **With a passkey:** "Sign in with a passkey" asks your device (or password manager) for any
  passkey this site knows. Nothing else is typed.
- **With your username and password.** On a browser this site has seen before, that's all.

Each browser that signs in becomes a **device**: the site gives it a secret, kept in the browser's
storage, and only a hash of it is stored. Passwords are hashed with scrypt. Sessions last 30 days.

Every session carries the account's **security epoch**. Recovering the account, changing or
setting the password, disconnecting a device, removing a passkey, replacing the owner key or
removing an encryption device moves the epoch on, which ends every other session at once (the
browser that made the change gets a fresh one). Changes to how you sign in, such as adding a
passkey or approving a new browser, also need proof it's you: a signature from one of your
encryption devices, which happens without asking, or else your password. Ten wrong passwords in
15 minutes lock password sign-in for a while; each attempt is recorded before it's checked.

## Confirming a new device

When the password is right but the browser is new, it must be confirmed with one of:

1. **A passkey** for this account.
2. **The recovery phrase or private key** (a signature over the site's challenge).
3. **Another device**: every signed-in device of yours shows "*Firefox on Linux* is signing in…
   and shows the code *123 456*. Is that you?". Approve it only if the code matches the one on the
   new device.
4. **An email code**, only for accounts made with an email before usernames, until they remove it.

Five wrong tries and the attempt is cancelled. An account with nothing set up to confirm with yet
(an older account's first sign-in since this update) has its browser trusted on the password.

**Settings → Sign-in and recovery** lists every signed-in device with how it was confirmed and
when it was last active. **Disconnect** signs it out at once; it has to be confirmed again to come
back. (These are sign-ins. The devices that hold encryption keys are managed separately, under
**Devices and keys**.)

## Passkeys

Two kinds can be added:

- **On this device:** stays on this computer or phone (WebAuthn's platform authenticator).
- **In a password manager:** synced to your other devices, like a phone passkey in iCloud Keychain
  or Google Password Manager, or in 1Password or Bitwarden.

Settings shows which each one is, from the passkey's backup flags. Passkeys are discoverable (no
username needed), user verification is preferred, and no attestation is asked for, so nothing
identifies the make of your device. The site stores each passkey's public key, its counter, and
the name you see.

## Getting back in

"Can't sign in?" on the sign-in page: your username, then your **recovery phrase or private key**,
or a **passkey**, and a new password. Every other session is signed out; your devices stay
connected (remove any you don't recognise). Whether a username exists isn't revealed.

An admin can also make a one-time reset link from the command line
(`docs/SELF_HOSTING.md`). That gets someone signed in, but not into their messages: those still
need their phrase or another of their devices.

## Accounts made with an email

Sites that ran Commonveil before usernames have accounts with an email. They keep working:

- They sign in with their email or their username, and password.
- In the app, they're told **email sign-in is going away**: that their account will sign in with
  their username and password, that their recovery phrase is how they get back in, and that a
  passkey or another device are optional extras. They're asked to set up a passkey and confirm
  their phrase.
- Once the phrase is confirmed, **Remove my email** deletes it. After that, only the username works.
- Email password resets work only until a passkey or the phrase is set up.

## What the site stores

For each account: a scrypt hash of the password, the owner public key, passkeys' public keys and
counters, hashes of device secrets and session tokens, devices' names (like "Firefox on Linux",
made from the browser's own description), and when each was added and last used. No IP addresses.
None of it can read a message.
