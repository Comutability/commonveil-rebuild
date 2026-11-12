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
