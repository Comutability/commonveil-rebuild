---
title: Sign-in, passkeys and recovery
summary: Your username and password, passkeys, confirming a new device, and getting back in.
section: Your account
order: 4
---

This is how accounts work on **self-hosted Commonveil sites**. On commonveil.online, you still sign in with your email for now.

Open **Settings → Sign-in and recovery** to see and change all of it.

## Signing in

Your account is a **username and password**. There's no email. You can sign in either way:

- **Sign in with a passkey**: your fingerprint, face or device PIN, and that's it.
- **Your username and password.**

## Passkeys

A passkey is a key your device keeps for this site. Nobody can phish it, and there's nothing to type. Add one in settings:

- **Add a passkey on this device** keeps it on this computer or phone only.
- **Add one to a password manager** syncs it to your other devices (iCloud Keychain, Google Password Manager, 1Password, Bitwarden and others).

You can have several, and remove any of them.

## A new device

The first time a browser signs in to your account, you'll be asked to **confirm it's you**, with one of:

- **A passkey.**
- **Your recovery phrase or private key.** It stays on the device: only a signature made with it is sent.
- **Another device.** On a device where you're already signed in, a bar asks whether you're signing in somewhere new, and shows a code. Approve it only if the code matches.

After that, it isn't asked again. **Signed-in devices** in settings lists every browser that's signed in, how it was confirmed, and when it was last used. **Disconnect** signs one out straight away.

## Recovery phrase and private key

Your **24-word recovery phrase** is made when you set up encryption, and you'll need it: it's how you get back in if you forget your password, and how you unlock your messages on a new device.

Your **private key** is the same secret written as one string, starting `cvkey1`. Keep whichever is easier to store safely: on paper, or in a password manager. In settings you can turn one into the other. Anyone who has either can take over your account, so never share them.

## Getting back in

Forgot your password? Choose **Can't sign in?** on the sign-in page. Enter your username, then your **recovery phrase or private key**, or use a **passkey**, and choose a new password. Every other session is signed out.

Nobody else can do this for you, not even the site's admin. If you lose your password, your phrase and every passkey and device, the account can't be recovered.

## Accounts made with an email

If you made your account with an email before usernames arrived, it still works: sign in with your email or your username. You'll be asked to **add a passkey** and **confirm your recovery phrase**, because email sign-in is going away. Once your phrase is confirmed, **Remove my email** deletes it from the site.
