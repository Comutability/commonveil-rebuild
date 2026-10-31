# Live browser tests

These drive the real app in headless Chromium against the real Base44 backend: sign-up through to
encrypted messaging, device linking, removal, recovery, reset warnings, groups and admin. They are
not part of `npm test` because they need signed-in test accounts and create real (test) records.

## What each script checks

| Script | Covers |
|---|---|
| `01-messaging.mjs` | Two new accounts set up keys, exchange messages, signatures verify, safety numbers match |
| `02-link-device.mjs` | Adding a second browser by approval; link codes match; history readable; new device's messages verify |
| `03-remove-device.mjs` | Removing a device rotates keys; no false key-change alarm for contacts; removed browser locked out, its keys kept until the person deletes them |
| `04-recover.mjs` | Wrong (valid) phrase refused; right phrase restores everything, before and after rotation |
| `05-reset-warning.mjs` | Account reset waits a week: the account's email is sent a notice, an existing browser shows the request and cancels it, a second request is left waiting. After the wait (`--finish`): old messages unreadable to the new identity; contacts warned and paused until review; the old browser told the account was reset; report filed |
| `06-groups.mjs` | Encrypted group names; members check who's in a group someone else made before sending; device-signed add; other members paused until they see who's new; newcomers aren't shown earlier messages; device-signed delete and leave |
| `07-admin.mjs` | Admin area without encryption setup; resolving a report; content editor; non-admins turned away |
| `08-public-pages.mjs` | Public pages on desktop (light) and phone (dark): no errors, no sideways scrolling |
| `09-accessibility.mjs` | axe-core WCAG 2 A/AA on public pages and signed-in screens, light and dark |
| `10-policy-report-delete.mjs` | A production build under its Content Security Policy: the policy and `security.txt` are served; public pages; an anonymous security report; a new member sets up and deletes their account; staff close the report; nothing of the app's own is blocked |
| `11-erase-test-accounts.mjs` | Cleaning up: Admin → Accounts lists deprovisioned test people and erases what they left (only usernames starting `e2e_`) |
| `12-access-rules.mjs` | Every table's read rule on the real platform: two new members each read only rows naming them and can't fetch the other's by id; visitors read nothing; private tables are closed |
| `14-policy-features.mjs` | The newer in-app features on a production build under its Content Security Policy: reactions, edits, the timer, the passcode lock, the data download and auto-delete, with nothing blocked |
| `13-features.mjs` | Replies, reactions and edits between Ann and Ben; disappearing messages (who set the timer, then gone everywhere once due, with `--expired`); group admins; message search on the device; a notification that says only "New message" and the unread count in the tab title; the passcode lock (locked after a reload, wrong passcode refused, Lock now); the data download (decrypted, no keys); auto-delete on and off; site search, saved pages and guide progress |

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
# A reset waits a week. Move Ben's waiting request into the past (Base44 entity tools, or the
# dashboard): ResetRequest where user_id is Ben's id and status is "waiting", effective_at = an hour ago.
node tests/e2e/05-reset-warning.mjs --finish
node tests/e2e/06-groups.mjs "<cat link>"
node tests/e2e/07-admin.mjs "<admin link>"
node tests/e2e/08-public-pages.mjs
node tests/e2e/09-accessibility.mjs
node tests/e2e/12-access-rules.mjs "<new member link>" "<another new member link>"
node tests/e2e/13-features.mjs            # CV_BEN_PROFILE=ben1 if 05 didn't run
# It prints a message to make disappear: set that Message's expires_at an hour back, then
node tests/e2e/13-features.mjs --expired <conversation path> "<that message>"
```

The scheduled clean-up behind disappearing messages can be run by hand against the preview:
`curl -X POST <api>/api/apps/<app-id>/functions/maintenance -H "Base44-Functions-Version: preview" -d '{"args":{"task":"expire"}}'`.

`10-policy-report-delete.mjs` needs a production build, because the policy only exists there (the editor preview runs
Vite's dev server). Build, serve `dist/` with `serve-dist.mjs`, and point the script at it with a newly provisioned member
(the script deletes that account) and the admin:

```bash
npm run build
CV_API_HOST=preview-sandbox--<app-id>.base44.app node tests/e2e/serve-dist.mjs 4173 &
CV_BASE_URL=http://localhost:4173 node tests/e2e/10-policy-report-delete.mjs "<new member link>" "<admin link>"
CV_BASE_URL=http://localhost:4173 node tests/e2e/14-policy-features.mjs "<another new member link>"
```

Scripts 01 and 06 claim the usernames `e2e_ann`, `e2e_ben` and `e2e_cat`. Deleted and erased accounts retire their usernames
for good, so set `CV_E2E_TAG` (up to 8 letters or numbers) to give each run its own: `e2e_ann_<tag>` and so on.
Browser profiles, screenshots and Ann's test phrase are kept in `CV_E2E_DIR` (default `/tmp/cv-e2e`).

## Cleaning up

Deprovision the test people (`DELETE /api/apps/{app_id}/users/provisions`), then run `11-erase-test-accounts.mjs` as the admin
(or open **Admin → Accounts** yourself) to erase what each left behind: their profiles, keys, devices, conversations and
messages go, the same way as when a member deletes their own account. Close any test security reports, then deprovision the
admin last. Erased usernames stay retired. Never run these scripts against an app with real members unless the test usernames
can't collide with theirs.
