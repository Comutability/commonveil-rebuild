# Security review, November 2026

An outside review (REPORT.md, with a verified evidence bundle) found 24 issues, CV-01 to CV-24.
All 24 are fixed on the `security-and-secure-net` branch. Each fix has a regression test that
fails on the old code; the table says where.

| ID | Severity | What was wrong | What changed | Test |
|---|---|---|---|---|
| CV-01 | High | Community key records were trusted again if their signature had been seen before, even with different contents | The verification cache is keyed by a hash of the whole record and the signer's current devices (`src/lib/secure/vouch.js`) | securityReview |
| CV-02 | High | A signed-in session alone could replace the recovery owner key | A new owner key needs the old key's signature, a device proof, or (only for an account with no keys yet) the password | identity |
| CV-03 | High | A disconnected device's access token still worked for adding passkeys and similar | Access tokens carry a security epoch; disconnecting, recovering or changing the password moves it on, and sign-in changes need a live session plus a proof | identity |
| CV-04 | High | Removing an encryption device left its community and voice secrets usable | Removing a device flags every chain it could read for rotation and ends its sessions; voice hellos need a certificate under the current key | servers |
| CV-05 | High | Losing access to a channel left read access and old keys | Access is rechecked on every read, and losing it rotates the channel's keys | servers |
| CV-06 | High | Polling skipped the newcomer history limit | Poll results go through the same per-message check as normal reads | servers |
| CV-07 | High | The first public registration on a self-hosted site could become its administrator | The first admin needs a one-time setup code printed on the server; `ADMIN_USERNAMES` and `ADMIN_EMAILS` are gone | identity |
| CV-08 | Medium | `OPEN_REGISTRATION=false` didn't stop sign-ups | Registration is refused unless open, invited, or the setup code is given | identity |
| CV-09 | Medium | A waiting check-in could be published early | Sending checks a private counter before looking at scheduled items | functions |
| CV-10 | Medium | Exact-name search ignored profile visibility | Search uses the same visibility rule as profiles | functions |
| CV-11 | Medium | Clearing an overwrite could restore a permission the actor can't grant | Overwrite changes are checked on every changed bit, not only the ones set | servers |
| CV-12 | Medium | Purge deleted messages in channels the moderator can't see | Purge only touches channels the moderator can manage | servers |
| CV-13 | Medium | Joining at the same moment could beat single-use invites | Uses are counted from the members who joined by that invite; extra joins are undone | servers |
| CV-14 | Medium | A bad key handout blocked a member until someone noticed | The client reports bad handouts; the grant is replaced and the sender isn't trusted for that member again | servers |
| CV-15 | Medium | Parallel wrong passwords could dodge the lockout | Each attempt is recorded before it's checked | identity |
| CV-16 | Medium | Signed-out challenges piled up | Signed-out challenges are signed tokens, nothing is stored; leftovers are swept | identity |
| CV-17 | Medium | Replies from other sites were fully read before the size limit applied | Replies are streamed and cut off at the limit; at most 16 run at once | securityReview |
| CV-18 | Medium | The Docker image installed runtime packages outside the lockfile | The runtime has its own reviewed lockfile and uses `npm ci` | Docker build |
| CV-19 | Medium | A failed update stayed "Updating…" | The app asks the updater how it went, with a 20 minute deadline | securityReview |
| CV-20 | Medium | Releases were offered before their images existed | The release workflow runs tests, then images, then the release | workflow |
| CV-21 | Medium | Pruning by name could delete the backup just made | Backups are pruned by age, always keeping the newest | securityReview |
| CV-22 | Medium | The type check didn't pass | A strict core type check runs as part of `npm run verify` | verify |
| CV-23 | High | `deploy/.env.example` wasn't in the repository | It's committed, and the installer writes `.env` safely | install |
| CV-24 | Low | Recovery options said whether an account had passkeys | Recovery never lists credentials | identity |

Also changed while fixing these: the updater refuses to go to an older version unless the server
has `UPDATER_ALLOW_DOWNGRADE=true`, writes `.env` atomically, and only reports a rollback as done
once the old version is healthy again. Email sending (SMTP) was removed from self-hosting, since
nothing needed it and it was one more secret to hold.

## Still open

- A newcomer on the Base44-hosted site can, for up to an hour, read the current live key of a
  channel through Base44's own entity reads. Message history limits still apply. Self-hosted
  sites don't have this.

## Our own follow-up review

After the fixes we went through the code again: dependencies (`npm audit`, 0 known
vulnerabilities in the app and in the Docker runtime), committed secrets (none), unsafe HTML and
code evaluation (none), how the self-hosted server serves files, its WebSocket limits, and the
tags it writes into pages (escaped). Fixed:

- **DNS rebinding in federation.** A site's address was checked, then looked up again when
  connecting, so a name could answer "public" for the check and "private" for the connection.
  Every outbound connection now checks the address it actually connects to.
- **Malformed addresses.** A request for a path with a broken `%` escape caused a server error;
  it's now a plain "Bad path". Paths are resolved against the site folder and must stay inside it.
- **Forwarded addresses.** When behind a proxy, the client's address is the one the proxy added
  (the last), not the first, which the client can set.

Known and accepted: ten wrong passwords lock password sign-in to an account for 15 minutes, so
someone who knows a username can lock its password out for a while. Passkeys and the recovery
phrase still work, and the alternative (no lockout) is worse.
