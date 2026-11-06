---
title: Run your own Commonveil site
summary: Host Commonveil on your own hardware with Docker, keep it up to date, and run it with no internet.
section: Running your own site
order: 1
---

Commonveil is free and open source (AGPL-3.0). Anyone can run their own site, on a small server, a home computer or a Raspberry Pi, with Docker. It's the same app, with the same end-to-end encryption, and it doesn't depend on us.

## Setting it up

You need a computer that stays on, Docker, and a domain name. In an empty folder, run:

```
curl -fsSLO https://raw.githubusercontent.com/Comutability/commonveil-rebuild/main/deploy/install.sh
sh install.sh
```

It asks for your domain and the username you'll use, then starts everything, including HTTPS. Open your site and create your account: it's the site's admin. The full guide, with every setting, is `docs/SELF_HOSTING.md` on GitHub.

## Updates

Every Commonveil release is published for self-hosted sites.

- When there's a new one, admins see a notice in **Site admin**, and **Updates** shows what's new with a button to install it.
- Turn on **Install updates automatically** to have it done in the background.
- Before each update the database is backed up, and if the new version doesn't start, the site goes back to the old one.

Release notes for every version are at [Releases](/releases).

## Other sites

Your site talks to other Commonveil sites, so its people can message people elsewhere ([People on other sites](/help/other-sites)). Under **Site admin → Other sites** you can see each site yours has talked to, and block any of them. Turn it off with `FEDERATION=false`.

## With no internet

A Commonveil site needs a network, not the internet. On a Raspberry Pi with its own Wi-Fi hotspot, everyone in range can make an account and chat, with nothing leaving the room. When it gets an internet connection again, anything that was waiting for other sites goes out. The set-up, including the certificate browsers need, is in `docs/SELF_HOSTING.md`.
