# Push notifications

Commonveil can tell a phone or computer that something new has arrived, even when the app is closed.
The design rule is that **a push carries nothing worth recording**: no sender, no conversation, no
words, no count. Push services (Google, Mozilla, Apple, Microsoft) and the operating system's
notification history see only that Commonveil had something new for this device, at that time.

This matters because notification text is stored outside the app. Operating systems keep a history of
it, and push providers can be compelled to hand over what passed through them. On some phones that
history has been read back by forensic tools long after the messages themselves were deleted. End-to-end
encryption protects a message in transit and on the server; it can't protect a copy the phone was told
to write into its notification log. So we never send one.

## What a person sees

- Title: **Commonveil**. Body: **New message** (a conversation) or **New activity** (anything else).
- Every notification has the tag `commonveil`, so each replaces the last: at most one is ever on the
  device. Waiting pushes also replace each other at the push service (the `Topic` header).
- Tapping it opens the app straight to the right conversation or channel (below).
- Quiet hours and focus make it silent. Those settings are mirrored into the browser's own storage for
  the service worker and never sent to us.
- The test push says "Notifications are on. This is all they'll ever say."

The service worker (`public/sw.js`) shows only these fixed words. Even if a push carried more, the
worker has no code path that could display it; `tests/serviceWorker.test.mjs` checks that.

## What a push carries

The payload is encrypted to the browser (RFC 8291, `aes128gcm`), so the push service can't read it.
Decrypted, it is:

```json
{ "v": 1, "k": "message", "c": "<one-time code>", "m": "<mute key>" }
```

- `k`, the kind: `message`, `conversation`, `activity`, `mention` or `test`.
- `c`, a random one-time code. On its own it means nothing.
- `m`, a mute key: `HMAC(mute_secret, "mute:" + place)`, cut to 16 characters. The browser made
  `mute_secret` and keeps it, so only that browser can tell which of its muted places a push is for. To
  anyone else it's noise, and a different value for each device.

There's no conversation ID, user ID, name or message text anywhere in it. `tests/notifications.test.mjs`
decrypts real pushes the way a browser would and checks for exactly that.

## Tapping a notification

1. The service worker opens `/app?push=<code>`, or, if Commonveil is already open, focuses that window
   and passes it the code.
2. The app, signed in, asks the server `notifications.open` with the code.
3. The server looks the code up by its SHA-256 hash, checks that it belongs to the person asking and
   hasn't expired, deletes it, and returns the path (for example `/app/c/<id>`). Anyone else's code, a
   used code or an expired code returns `/app`.

So the place is only ever revealed to the signed-in owner, over the normal encrypted connection, and
never touches the push service or the notification log. Codes last a week and work once.

## What the server keeps

| Record | Fields | Gone when |
| --- | --- | --- |
| `PushSubscription` | account, sign-in device, push address, the browser's public push keys, the mute secret, time of the last push, and the servers this browser wants pushes from (every message, or only @mentions) | turned off, signed out, the push service says the address is gone (404/410), or the account is deleted |
| `PushCode` | account, a hash of the code, the path, expiry | used, a week passes, or the account is deleted |

Both are backend-only: no browser can read them. A push address is a capability for sending to that
browser and nothing more, but it is still treated as private.

The site's VAPID signing key (RFC 8292) is made on first use and stored as the `push-vapid` secret. Its
public half is what browsers subscribe with; the private half never leaves the server.

## Limits that keep it quiet

- At most one push per device every 20 seconds. A burst of messages becomes one notification.
- The sender's own devices aren't notified.
- Conversations, group messages, server channel activity and @mentions can push. The server
  checks the recipient can read a channel and that this browser asked for that server's pushes of
  that kind (below), and each device applies its own channel preference (`All messages`,
  `Only @mentions` or `Nothing`) using an opaque local HMAC token.
- Channel notification fanout currently covers the first 200 server members per message; larger
  communities need a paginated queue before every member can be guaranteed a push.
- `Send a test` targets only the requesting browser, not the account's other devices. Its
  result says whether the request was accepted, rejected (including safe HTTP status), timed out,
  could not connect or could not be prepared. The test does not pretend that an accepted request
  proves the browser displayed a notification.
- A failed or rejected push does not start the 20-second cooldown, and a server-side diagnostic
  records only the outcome, counts and safe HTTP status code, never addresses, keys or contents.
- Hosted Base44 functions use an edge runtime which supports `redirect: "manual"`, not
  `redirect: "error"`. Commonveil uses the supported mode and explicitly refuses redirect
  responses for Web Push, preserving the push host allowlist without suppressing outbound sends.
- If a device-specific test reports a transport failure, the server makes one **fixed-host** HEAD
  request to `https://fcm.googleapis.com/` without any subscription information or credentials.
  Its result distinguishes general Google push-service reachability from a failed signed Web Push
  request. The failure category is a fixed safe label (permissions, DNS, TLS, connection, invalid
  request or unclassified), never an exception message or a browser push address.
- Pushes are sent only to the browsers' real push services (an allowlist of their hostnames over HTTPS
  on the standard port), so the server can't be made to post anywhere else.
- A push service that's down, slow or refusing never delays or fails the message itself.

## Mention-routing metadata and privacy

A channel message remains end-to-end encrypted. To make a browser alert for an @mention while the
recipient's app is closed, the sending device includes an **ephemeral routing hint** alongside the
ciphertext: the IDs of directly mentioned accounts and roles, or an `@everyone` flag. The server can
see **who was targeted** by a mention (this is additional metadata), but never the text, names or
contents. The hint is not saved with the message or included in the Web Push payload. A modified
sending client could lie about a mention, so the server validates membership, permissions and
rate limits rather than treating the hint as proof of decrypted content.

## Which servers push to a browser

From 0.24.23 each browser tells the site, per server, which pushes it wants
(`notifications.alerts`): **every new message**, **only @mentions**, or none. The app works this out
from its own settings: a server's most talkative channel decides (so a server muted as a whole asks
for nothing, and a server whose one watched channel is set to `All messages` asks for everything).
The site then pushes a server's activity only to browsers that asked for it, instead of to every
member who can read the channel. A quiet server costs its members nothing, and a busy one no longer
wakes every phone in it for each message.

This is a small, deliberate disclosure: the site learns, per browser, which of your servers you want
pushes from and at which of those two levels. It already knows which servers you're in; it doesn't
learn anything per channel. A browser that hasn't said yet (an app from before 0.24.23, until it is
next opened) gets @mentions from every server and other activity from every server except the
site's default one, which are the app's own defaults.

The recipient's choice of channels to mute or watch still stays on their device. A browser HMAC token
lets the service worker match a generic push to a local channel rule without receiving a channel ID
in the push. An unknown channel defaults to no visible server alert.

## Turning it on and off

**Settings → Notifications → Push notifications.** It's off until turned on, and it's per device.
Turning it on asks the browser's permission, subscribes, and registers the address. Turning it off, or
signing out, unsubscribes the browser and deletes the address.

On iPhone and iPad, Safari only allows push for apps added to the Home Screen
([INSTALLING.md](INSTALLING.md)), so the setting says so until then.

## Self-hosted sites

Push works the same way. The VAPID contact (`subject`) is the site's own URL. Nothing is sent to us.

## Known limits

- Members on other Commonveil sites (federation) aren't pushed to yet; they see new messages when they
  open the app.
- A push still tells the push service that this device got something from this site at that moment. The
  20-second limit and collapsing keep that coarse; turning push off removes it entirely.
- The operating system still records that Commonveil showed a notification. That's all it can record.
