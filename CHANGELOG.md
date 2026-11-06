# Changelog

Every release of Commonveil. The newest is first. Versions follow [semantic versioning](https://semver.org): a new
minor version (0.x.0) adds features; a patch (0.x.y) fixes things.

> Generated from `src/content/releases.json` by `scripts/release.mjs`. Edit that file, not this one.

## [0.19.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.19.0): Sign in your way, install the app, and private push notifications

_2026-11-06_

- New accounts are a username and password, on every Commonveil site. No email needed.
- Accounts made with an email before today still sign in with it, and can add a username and password, or a passkey, and then remove the email.
- Joining asks you to confirm you're 16 or older. Accounts found to belong to someone younger are closed.
- Terms of Use, in plain language, linked from sign-up and every page.
- Install Commonveil as an app on your phone, tablet or computer: its own icon and window, opening straight to your messages, still this website with no app store.
- Push notifications, off until you turn them on. They say only "New message", never who it's from, which conversation or what was said, so your phone and its push service keep no record. Tapping one opens the right conversation.
- Better for screen readers and keyboards: a skip link in the app, clearer names for buttons and badges, and higher-contrast avatars.
- Easier to find: every page that works without signing in has its own title, description and link preview, with a sitemap for search engines. The app is never indexed, and nor are invites, reset links or people's profiles.
- New Help Centre article: installing the app. The notifications article now covers push.

## [0.18.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.18.0): Offline mode

_2026-11-06_

- Keep writing with no connection: each message is encrypted and signed on your device straight away, waits there, and goes out when you're back, showing the time you wrote it.
- Offline mode in settings stops the app reaching the server until you turn it off. Everything you send in the meantime waits, already encrypted.
- If something changed while you were away, a waiting message is marked "Not sent", with Send again or Delete.
- Self-hosted sites hold messages for other sites they can't reach, and pass them on when they can, for up to a week.
- A self-hosted site can run on a small computer with its own Wi-Fi, so people nearby can chat with no internet. The guide is in docs/OFFLINE.md and docs/SELF_HOSTING.md.
- New Help Centre articles: offline mode, people on other sites, sign-in and recovery, and running your own site.

## [0.17.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.17.0): Commonveil Identity

_2026-11-06_

- On self-hosted sites, accounts are a username and password, with no email.
- Sign in with a passkey, kept on one device or synced by a password manager.
- A browser signing in for the first time is confirmed with a passkey, your recovery phrase or private key, or from a device you're already signed in on. Signed-in devices are listed in settings, where you can disconnect any of them.
- Your private key is your recovery phrase written as one string: either proves the account is yours. Getting back in takes one of them, or a passkey.
- Accounts made with an email still work, and are asked to add a passkey and confirm their phrase before email sign-in goes away.

## [0.16.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.16.0): Run it yourself, and talk across sites

_2026-11-06_

- Commonveil can run on your own hardware with Docker, without Base44: one install script, HTTPS included.
- Self-hosted sites show admins when a new release is out, with an update button, and can update themselves automatically. Each update is backed up first and undone if it doesn't start.
- Self-hosted sites talk to each other with the Commonveil Protocol: everyone has an address like @ann.chat.example.com that also opens their profile, and conversations and servers work across sites, still end-to-end encrypted.
- Browse and join servers listed on other sites from Discover.
- Profile pictures.
- The message box grows with longer messages, and can be expanded.
- The home page compares Commonveil with other privacy-focused chat apps.

## [0.15.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.15.0): A tighter site, with release notes

_2026-11-05_

- Guides, learning paths, the wiki and the blog have been removed, so the site is about Commonveil itself. Their old addresses now lead to the Help Centre.
- Release notes for every version, from 0.1.0 onwards, on the site and as tags on GitHub.
- The site's version is shown at the bottom of every page.
- Commonveil is now free software, under the AGPL-3.0.

## [0.14.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.14.0): Help Centre

_2026-11-05_

- A Help Centre with an article for every feature: what it's for, how to use it and what it shares.
- The complete guide on one page, to print or download, and as docs/USER_GUIDE.md on GitHub.
- "How this works" links from settings pages to the right article.

## [0.13.1](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.13.1): Scheduled tasks fixed

_2026-11-05_

- Scheduled tasks now run reliably: scheduled messages, check-ins and self-destructing conversations every 5 minutes, disappearing messages every 30 minutes, and opt-in account deletion daily.
- The self-destruct menu no longer lists "Off" twice.

## [0.13.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.13.0): Send later, safety check-ins and self-destructing chats

_2026-11-05_

- Send later: write now, deliver from a minute to a year ahead.
- Safety check-ins: a message that sends itself unless you tap "I'm OK" in time.
- Self-destructing conversations, deleted for everyone at a time you choose.
- A privacy report showing everything the service holds about you, with a privacy checkup.
- Quiet hours and focus for notifications, kept on your device.

## [0.12.1](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.12.1): Names in moderation

_2026-11-05_

- Reports and cases show the names of members who aren't in the member list, instead of "Member".

## [0.12.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.12.0): Security audit and built-in moderation

_2026-11-05_

- Fixes from a full security review: channel permissions, private channels, call membership checks and safer word matching.
- Reports to a server's moderators, encrypted to them alone, and escalation to the Commonveil team.
- Numbered cases, warnings with automatic steps, flood and raid protection, staff limits, temporary bans and message purges.

## [0.11.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.11.0): Files, voice messages, events and more

_2026-11-05_

- Encrypted files and voice messages.
- A server's own emoji and stickers, AutoMod, threads and events.
- Optional online status and typing, stage channels, and calls in conversations.

## [0.10.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.10.0): Video and screen sharing

_2026-11-05_

- Turn your camera on or share your screen in calls, with every video frame encrypted too.

## [0.9.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.9.0): Polls, inbox and quick switcher

_2026-11-05_

- Polls, every emoji as a reaction, an inbox for mentions and unread channels, saved messages, a quick switcher (Ctrl + K), server folders, private notes and forwarding.

## [0.8.2](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.8.2): Calls recover from network drops

_2026-11-05_

- Calls find a new route by themselves after a network drop.

## [0.8.1](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.8.1): Calls survive a quick reconnect

_2026-11-05_

- You keep your place in a call through a quick reconnect.

## [0.8.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.8.0): Encrypted voice calls

_2026-11-05_

- Peer-to-peer voice calls in voice channels, with signed connections and every audio frame encrypted with the channel's keys.

## [0.7.1](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.7.1): Server settings fixes

_2026-11-05_

- Server settings load correctly after a reload, a note about staff in member lists, and clearer text while waiting for keys.

## [0.7.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.7.0): Servers and the community hub

_2026-11-05_

- Encrypted servers with channels, roles, invites and Discover, the Commonveil Community server, and post-quantum hybrid keys, now live.

## [0.6.1](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.6.1): Faster server updates

_2026-11-05_

- Server changes are checked separately from messages.

## [0.6.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.6.0): A new layout

_2026-11-05_

- A server rail, channel list, chat, forums, tickets and settings, laid out like Discord.

## [0.5.1](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.5.1): Who hands out keys

_2026-11-05_

- Servers choose whether any member's app or only staff hand keys to newcomers.

## [0.5.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.5.0): Post-quantum keys and encrypted servers

_2026-11-05_

- Keys sealed with ML-KEM-768 and P-256 together, and the groundwork for encrypted servers.

## [0.4.2](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.4.2): Checks after going live

_2026-10-31_

- The live site was checked, and the security policy test fixed.

## [0.4.1](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.4.1): Live, with updated privacy pages

_2026-10-31_

- The new features were verified on the live site, and the Privacy and Security pages updated.

## [0.4.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.4.0): Replies, reactions and a passcode lock

_2026-10-30_

- Replies, reactions and edits; disappearing-message timers and group admins; alerts; message search on your device; a passcode lock; a download of your data; opt-in auto-delete; and site search.

## [0.3.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.3.0): Timers, admins and security emails

_2026-10-30_

- Disappearing messages, group admins, security emails, opt-in deletion of unused accounts and scheduled clean-up, on the server.

## [0.2.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.2.0): Protocol version 2

_2026-10-30_

- Fixes from a review of the encryption protocol, each member reading with their own access, and a staff tool for erasing what removed sign-ins left behind.

## [0.1.1](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.1.1): Signed group changes

_2026-10-29_

- Changes to groups need a device signature, membership can be paused, a stale-keys fix, and a browser test suite.

## [0.1.0](https://github.com/Comutability/commonveil-rebuild/releases/tag/v0.1.0): The rebuild

_2026-10-29_

- Commonveil rebuilt from scratch: end-to-end encrypted direct messages and groups, device linking, a 24-word recovery phrase and safety numbers.
- The public site, with content brought over from the old one.
