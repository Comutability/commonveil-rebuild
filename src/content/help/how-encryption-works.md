---
title: How the encryption works
summary: In plain language: what end-to-end encryption protects, what Commonveil can and can't see, and the limits.
section: Privacy and safety
order: 5
---

## The short version

Your device locks every message before it leaves, using keys that only the people in the conversation hold. Commonveil stores and delivers locked messages it can't open. Even if someone took a full copy of Commonveil's database, they'd have ciphertext, not conversations.

## Your keys

- When you set up a device, it makes its own private keys. They **never leave your devices**.
- Your account has a key history: every key you've ever used, each one signed by the one before. The people you talk to check that history, and [safety numbers](/help/safety-numbers) let you check it together.
- A new device only gets your keys if one of your existing devices approves it after you compare a code, or if you type your recovery phrase.
- Your **recovery phrase** unlocks an encrypted backup of your keys. Commonveil doesn't have a copy.

## What's encrypted

Messages, replies, reactions, edits, polls and votes, files and voice messages, group names, call audio and video, and everything inside a server: its name and description, channel and role names, nicknames, rules, events, emoji, stickers, AutoMod settings, moderation reasons and reports to moderators.

Keys are sealed with a **post-quantum hybrid** (ML-KEM-768 combined with P-256), so an attacker would have to break both. Messages recorded today stay protected against a future quantum computer.

## What Commonveil can see

It needs some information just to work, and it keeps that to a minimum:

- your sign-in address, username, and the profile you choose to fill in (profiles aren't encrypted);
- your devices' names and the day each was last used;
- who is in which conversation and server, and when messages are sent, roughly how big they are, and who each was locked for;
- settings it has to enforce: group admins, timers and who set them, roles and permissions, bans and timeouts;
- when scheduled messages and check-ins are due and for whom, and when a conversation will self-destruct;
- who joined which call and when;
- for servers listed in Discover, their public card.

It **never** sees what anything says, and it doesn't collect contacts, phone numbers, location, or advertising or tracking identifiers. The [privacy report](/help/privacy-report) shows what it holds about you.

## What it can't protect against

- **The people you talk to.** Anyone in a conversation can read it, and can copy or screenshot it, even disappearing messages.
- **Your own device.** If someone can use your unlocked device, or installs software on it, they can read what you can. A [passcode lock](/help/security) helps.
- **Before you compare safety numbers.** The very first time you talk to someone, you trust that the keys you're given are theirs. Comparing safety numbers removes that trust.
- **The app itself.** Commonveil runs in your browser, so you're trusting the code the site sends you. Its source is published so it can be checked.
- **Metadata.** It can see who talks to whom and when, as above.
- **Delivery.** It could delay or drop messages, including a scheduled message or a check-in. It can't read or change them without it showing.

## No audit yet

The design and code are tested, but not yet independently audited. The full technical details are in the [complete guide](/help/guide) and the protocol documents in the source repository.
