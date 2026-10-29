# Live browser tests

These drive the real app in headless Chromium against the real Base44 backend: sign-up through to
encrypted messaging, device linking, removal, recovery, reset warnings, groups and admin. They are
not part of `npm test` because they need signed-in test accounts and create real (test) records.

## What each script checks

| Script | Covers |
|---|---|
| `01-messaging.mjs` | Two new accounts set up keys, exchange messages, signatures verify, safety numbers match |
| `02-link-device.mjs` | Adding a second browser by approval; link codes match; history readable; new device's messages verify |
| `03-remove-device.mjs` | Removing a device rotates keys; no false key-change alarm for contacts; removed browser locked out |
| `04-recover.mjs` | Wrong (valid) phrase refused; right phrase restores everything, before and after rotation |
| `05-reset-warning.mjs` | Account reset: old messages unreadable to the new identity; contacts warned and paused until review; report filed |
| `06-groups.mjs` | Encrypted group names; device-signed add; other members paused until they see who's new; newcomer can't read history; device-signed delete and leave |
| `07-admin.mjs` | Admin area without encryption setup; resolving a report; content editor; non-admins turned away |
| `08-public-pages.mjs` | Public pages on desktop (light) and phone (dark): no errors, no sideways scrolling |
| `09-accessibility.mjs` | axe-core WCAG 2 A/AA on public pages and signed-in screens, light and dark |

## Running them

1. Install the tools once, outside the app: `npm i playwright@1.56.0 axe-core@4.10.3` and `npx playwright install chromium`
   (on a bare Linux box, `npx playwright install-deps` too).
2. Provision test accounts in the app (Base44 platform API `POST /api/apps/{app_id}/users/provisions`): three people with role
   `user` and one with role `admin`. Use addresses at `example.com`, which never receive mail.
3. For each script that takes arguments, mint a single-use sign-in link just before running it with
   `POST /api/apps/{app_id}/embed-url` (`{"email": "...", "target": "live_preview"}`). Links expire after 60 seconds.
4. Run in order, with `CV_BASE_URL` set to the preview or site URL:

```bash
export CV_BASE_URL=https://preview-sandbox--<app-id>.base44.app
node tests/e2e/01-messaging.mjs "<ann link>" "<ben link>"
node tests/e2e/02-link-device.mjs "<ann link>"
node tests/e2e/03-remove-device.mjs
node tests/e2e/04-recover.mjs "<ann link>"
node tests/e2e/05-reset-warning.mjs "<ben link>"
node tests/e2e/06-groups.mjs "<cat link>"
node tests/e2e/07-admin.mjs "<admin link>"
node tests/e2e/08-public-pages.mjs
node tests/e2e/09-accessibility.mjs
```

The usernames in `lib.mjs` (`e2e_ann`, `e2e_ben`, `e2e_cat`) are claimed by script 01 and 06; change them if they're taken.
Browser profiles, screenshots and Ann's test phrase are kept in `CV_E2E_DIR` (default `/tmp/cv-e2e`).

## Cleaning up

Deprovision the test accounts (`DELETE /api/apps/{app_id}/users/provisions`) and delete their `Profile`, `AccountKey`, `Device`,
`KeyEnvelope`, `Conversation`, `Message`, `Block` and `Report` rows. Never run these against an app with real members unless the
test usernames can't collide with theirs.
