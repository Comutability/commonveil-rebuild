# Running Commonveil yourself

Commonveil runs on your own hardware as a Docker deployment. It doesn't need Base44, or anything
else of ours, and it's the same app with the same end-to-end encryption as the hosted one. Your
site gets its own accounts, and can talk to other Commonveil sites (see `docs/FEDERATION.md`).

This guide covers: what you need, installing, settings, accounts and admins, updates, backups,
talking to other sites, running a site with no internet, and troubleshooting.

**Secure Net is independent of Commonveil.** This Docker stack installs
Commonveil, the first application to adopt the protocol. It is NOT a
generic Secure Net relay appliance and has not yet demonstrated live,
third-party CVP-019 outbox/inbox/deliver interoperation. See
SECURE_NET_INTEGRATION.md for the independent developer and relay model.
Commonveil's older version 1 federation remains available separately.

## What you need

- A computer that stays on: a small VPS, a home server or a Raspberry Pi 4 or 5 is plenty for a
  community of a few hundred. 1 GB of memory and a few GB of disk is enough to start. Images are
  built for `linux/amd64` and `linux/arm64`.
- Docker Engine with Compose v2 (`docker compose version` should work).
- A domain name, with DNS you can change. You need two records pointing at the computer:
  - `chat.example.com` (your site), and
  - `*.chat.example.com` (people's addresses, like `alice.chat.example.com`). Optional, but
    without it addresses work in the app and not in a browser.
- Ports 80 and 443 open to the internet, so the site can get HTTPS certificates from Let's
  Encrypt. (For a site with no internet at all, see [Running a site with no internet](#running-a-site-with-no-internet).)

## Installing

In an empty folder (for example `/opt/commonveil`):

```bash
curl -fsSLO https://raw.githubusercontent.com/Comutability/commonveil-rebuild/main/deploy/install.sh
sh install.sh
```

It asks for your domain and an email address for Let's Encrypt, writes `.env`, starts everything
and prints a one-time **setup code**. Open `https://chat.example.com`, create your account and
enter the code: that account becomes the site's admin. Nobody can make an account until then, so
a stranger can't get there first. If you lose the code, print it again with
`docker compose exec app commonveil-server setup-code`.

To do it by hand instead: copy `deploy/docker-compose.yml`, `deploy/Caddyfile` and
`deploy/.env.example` (as `.env`) from this repository, fill in `.env`, then run
`docker compose up -d`.

The stack has three containers:

| Container | What it does |
| --- | --- |
| App | Commonveil login, messaging, realtime rooms and existing Commonveil federation, backed by independent Secure Net Rust protocol code. Not a generic CVP-019 relay. Data lives in the Docker volume. |
| `caddy` | HTTPS. Gets and renews certificates by itself, including one for each person's address the first time it's visited (only for accounts that exist: it asks the app). |
| `updater` | Applies updates when an admin asks, or automatically if you turn that on. It's the only container with access to Docker. |

## Settings

All settings are in `.env`. After changing one, run `docker compose up -d`.

| Setting | What it's for |
| --- | --- |
| `SITE_DOMAIN` | Your site's address, without `https://`. |
| `HANDLE_DOMAIN` | People's addresses are `username.HANDLE_DOMAIN`. Leave empty to use `SITE_DOMAIN`. |
| `SITE_NAME` | The name shown to other sites and in passkey prompts. |
| `ACME_EMAIL` | Let's Encrypt sends certificate notices here. |
| `DEFAULT_SERVER_ADMINS` | Admins of the Commonveil Community server every new account joins, by username. Only accounts that are site admins count. |
| `SNIP_FORUM` | `on` adds a proposals forum to the community server, with one post per Secure Net Improvement Proposal on GitHub. Your server then reads GitHub's public API about every 20 minutes. Off by default. See [SNIP_FORUM.md](SNIP_FORUM.md). |
| `OPEN_REGISTRATION` | `false` stops new sign-ups once the first admin exists. The first admin always needs the setup code. |
| `FEDERATION` | `false` keeps your site to itself: no other site can reach it, and its people can't reach others. |
| EXPERIMENTAL_TRANSFER_STAGING | Experimental Secure Net draft ciphertext and encrypted-report staging, explicitly disabled by default. Use only on an isolated private test instance, never a production site. It does **not** move accounts or messages. See [the limitations](MIGRATION_STAGING.md). |
| EXPERIMENTAL_RECIPIENT_CONSENT | Additional explicit private-test-only gate for signed recipient device request and owner grant storage. Requires the transfer staging flag as well. Does not prove private KEM key ownership, enrol a device, import messages or cut over a mailbox. Defaults to false. |
| VOICE_TURN_URLS, VOICE_TURN_SECRET | Optional coturn REST relay for audio/video calls when peers cannot connect directly. Configure both together on a trusted TURN server; the secret must be at least 32 characters. Rust issues six-hour per-account HMAC-SHA1 credentials after checking voice-call permissions. Leave blank for direct-only calls. |
| `COMMONVEIL_VERSION` | Which release runs. The updater changes it. `latest` follows each new release. |
| `UPDATER_ALLOW_DOWNGRADE` | `true` lets the updater go back to an older release. Leave it off otherwise. |
| `COMMONVEIL_DIR`, `UPDATER_TOKEN` | This folder's full path, and the secret the app and the updater share. `install.sh` sets both. |

Advanced settings you can add to the `app` service's environment in `docker-compose.yml`:
`UPDATE_CHECK_HOURS` (how often to look for releases, default 6), `UPDATE_FEED` (where to look),
`FEDERATION_ALLOW_PRIVATE` (allow talking to sites on private networks, for local sites only),
`EXTRA_CA_CERTS` (a PEM file of certificate authorities to trust besides the public ones, for local
sites only), and `SECRET` (otherwise one is made and kept in the data volume).

## Accounts and admins

Accounts on a self-hosted site are a **username and password**, with **passkeys** for everyday
sign-in and a **24-word recovery phrase** (or its other form, the **private key**) that proves the
account is yours. There's no email. A browser that signs in for the first time has to be confirmed
with a passkey, the phrase or private key, or from a device that's already signed in. People
manage all of this in **Settings → Sign-in and recovery**. `docs/IDENTITY.md` explains how it
works.

Admins see **Site admin** in settings: reports, security reports, help content, updates, and the
other sites this one talks to. Being an admin doesn't let anyone read messages: those are
encrypted on people's devices.

Commands for the command line (run them in your Commonveil folder):

```bash
docker compose exec app commonveil-server make-admin <username>
docker compose exec app commonveil-server setup-code                  # shows the first-admin code, if still unused
docker compose exec app commonveil-server reset-password <username>   # prints a temporary password and signs them out everywhere
docker compose exec app commonveil-server backup
docker compose exec app commonveil-server version
```

Only use `reset-password` once you're sure who you're talking to: a new password signs someone in,
but they still need the person's recovery phrase or another of their devices to read messages.
Restart the app afterwards (`docker compose restart app`) for it to take effect.

## The app and push notifications

People can install the site as an app on their phone or computer, and turn on push notifications.
There's nothing to set up: the manifest, icons and service worker ship with the image, and the site
makes its own push signing key the first time it's needed (kept in `/data`). Both need HTTPS, which
the installer sets up.

Pushes go from your server to the browsers' own push services (Google, Mozilla, Apple, Microsoft), so
the server must be able to reach them over HTTPS. A push says only "New message" and carries a one-time
code; nothing about who, where or what. `docs/NOTIFICATIONS.md` and `docs/INSTALLING.md` explain both.
On a site with no internet, push simply doesn't arrive; everything else works.

## Updates

Every release of Commonveil is published as a Docker image (`ghcr.io/comutability/commonveil`) and
announced on GitHub. Your site checks for new releases every few hours.

- When there's one, admins see a notice at the top of **Site admin**, and the **Updates** tab shows
  what's new with an **Update to X** button.
- **Install updates automatically** (on the same tab) installs new releases by itself, in the background.
  It's off until you turn it on.
- Before each update, the database is copied to `backups/` in the data volume. If the new version
  doesn't start properly within two minutes, the updater goes back to the one before.

To update by hand instead: set `COMMONVEIL_VERSION` in `.env` to the version you want and run
`docker compose pull && docker compose up -d`. Release notes are on the site at `/releases`, in
`CHANGELOG.md`, and on GitHub.

From 0.24.0 the server is a single program written in Rust instead of Node.js. Updating to it needs
nothing from you: it uses the same data volume, the same settings and the same keys, so people stay
signed in and other sites still know yours. The admin commands (under [Accounts and admins](#accounts-and-admins))
changed from `node server/index.mjs` to `commonveil-server`. If you set `NODE_EXTRA_CA_CERTS` (see [Running a site with no internet](#running-a-site-with-no-internet)),
it still works; `EXTRA_CA_CERTS` is its new name. To update the updater as well (it's Rust too now),
run `docker compose pull updater && docker compose up -d updater` once.

### Experimental Docker preview

The continuous-integration workflow builds an explicitly opt-in developer
image at ghcr.io/comutability/commonveil:edge and a matching updater
image, only after the website, Rust, WebAssembly and Docker checks pass.
It also publishes an immutable edge-COMMIT-SHA tag. The stable :latest
and numbered release tags are not changed by this preview process.

Do not run an edge image on an existing site's production account volume.
Use a disposable private test site with an independent data volume and
verified backups. Experimental staging remains disabled by default,
even in edge. It does not migrate identities, conversation history or inboxes.

The stable Docker release workflow remains separate from these previews.

## Backups

Everything is in the `data` volume: the database (`commonveil.db`), uploaded files (all
encrypted on people's devices before upload) and the site's keys.

```bash
docker compose exec app commonveil-server backup      # copies the database to /data/backups
docker run --rm -v commonveil_data:/data -v "$PWD":/out alpine tar czf /out/commonveil-data.tgz -C /data .
```

To restore, stop the app (`docker compose stop app`), put the files back into the volume, and start
it again. Keep backups somewhere safe: the database holds who talks to whom (not what they say),
and the site's federation key, which other sites know it by.

## Talking to other sites

It's on by default. People can start conversations with anyone on another Commonveil site by their
address (`@alice.other.example`), and join servers listed on other sites from **Discover**. Each
site keeps its own people's accounts; messages stay end-to-end encrypted the whole way.
`docs/FEDERATION.md` is the protocol.

Admins see each site theirs has talked to under **Site admin → Other sites**, and can block one. If a
site's key changes, yours stops talking to it until an admin accepts the new key there: do that
only once its admin has told you the change was expected.

To keep your site to itself, set `FEDERATION=false`.

## Running a site with no internet

A Commonveil site doesn't need the internet, only a network. On a small computer with its own Wi-Fi,
everyone in range can make accounts on it and chat, with nothing leaving the room. When it gets an
internet connection again, anything its people sent to other sites, and couldn't deliver, goes out
by itself. `docs/OFFLINE.md` explains the parts and their limits; in short:

1. Put Commonveil on a Raspberry Pi (or any small computer) as above, and make the computer a Wi-Fi
   hotspot (for example with NetworkManager: `nmcli device wifi hotspot ssid Commonveil password <something>`).
2. Browsers only run Commonveil's encryption on HTTPS pages, so the site needs a certificate
   phones and laptops accept. Either:
   - **a real domain, set up while you still have internet:** point `chat.example.com` at the
     computer's local address (for example `10.42.0.1`), and get a certificate with a DNS
     challenge (Caddy's DNS plugins do this). It lasts 90 days; or
   - **Caddy's own certificate authority:** in the Caddyfile, use `tls internal` for your site's
     block, then install Caddy's root certificate (`docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt`)
     on each device that will use the site.
3. Leave `FEDERATION=true`. If the site will talk to other local sites (on the same network),
   add `FEDERATION_ALLOW_PRIVATE: "true"` to the app's environment, and give each site the other's
   root certificate: mount the file into the app container and set `EXTRA_CA_CERTS` to its path
   there (a PEM file; it can hold several certificates).

People with accounts on other sites can't sign in to a local one: they make an account there.
Their messages on their own site wait in their browser (offline mode) and go out when it can be
reached again.

## Building it yourself

```bash
docker build -t commonveil:local .                                   # from a clone of this repository
docker build -t commonveil-updater:local -f updater/Dockerfile .     # the updater, if you want it too
```

Then set `image: commonveil:local` for the `app` service (and `commonveil-updater:local` for
`updater`). Without Docker you need Rust (1.88 or later) for the server and Node.js (24, or 26.12.1
or later) to build the site, then, in the clone:

```bash
npm ci
VITE_COMMONVEIL_BACKEND=selfhost npx vite build --outDir dist-selfhost
cargo build --release --manifest-path rust/Cargo.toml -p commonveil-server
DATA_DIR=./data SITE_URL=http://localhost:8080 DIST_DIR=./dist-selfhost ./rust/target/release/commonveil-server
```

Run it from the clone's folder (it reads `package.json` and `base44/entities` there), or set
`APP_ROOT` to that folder. `http://localhost` works for trying it out; anywhere else needs HTTPS.

## Moving from the hosted site

There's no automatic move from commonveil.online to a self-hosted site, because the hosted site
doesn't keep anything it could hand over that would be useful: messages are encrypted on people's
devices. People who move make an account on the new site; with both sites talking to each other,
they can keep talking to people who stay.

## Troubleshooting

- **The site doesn't load, or certificates fail:** check DNS points at this computer and ports 80
  and 443 are open: `docker compose logs caddy`.
- **People's addresses don't open in a browser:** add the wildcard DNS record (`*.chat.example.com`).
- **"Can't reach the update service":** the updater container isn't running, or `UPDATER_TOKEN`
  differs between it and the app: `docker compose ps`, then `docker compose up -d`.
- **Another site says yours is unreachable:** it must reach `https://SITE_DOMAIN/.well-known/commonveil`.
- **Everything else:** `docker compose logs app`. Security problems: report them privately at
  `/security/report` on commonveil.online.
