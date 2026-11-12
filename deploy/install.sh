#!/bin/sh
# Sets up Commonveil in this folder: asks for your domain, writes .env, starts it, and shows the
# one-time setup code for creating the site's first (admin) account.
#   curl -fsSLO https://raw.githubusercontent.com/Comutability/commonveil-rebuild/main/deploy/install.sh && sh install.sh
# COMMONVEIL_REF picks which version's files to use (a release tag such as v0.20.0, or main).
set -eu
umask 077
REF="${COMMONVEIL_REF:-main}"
REPO="https://raw.githubusercontent.com/Comutability/commonveil-rebuild/$REF/deploy"

command -v docker >/dev/null 2>&1 || { echo "Install Docker first: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is needed (docker compose ...)."; exit 1; }

# All files come from the same version, so they always match each other.
for f in docker-compose.yml Caddyfile .env.example; do
  if [ ! -f "$f" ]; then
    curl -fsSL "$REPO/$f" -o "$f.part" && mv "$f.part" "$f"
  fi
done

if [ -f .env ]; then
  echo ".env already exists: starting with it."
else
  printf "Your site's domain (for example chat.example.com): "; read -r domain
  printf "An email address for certificate notices from Let's Encrypt: "; read -r email
  case "$domain" in *[!A-Za-z0-9.-]*|"") echo "That doesn't look like a domain."; exit 1 ;; esac
  token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  # Written whole, readable only by you, then moved into place.
  sed -e "s|^SITE_DOMAIN=.*|SITE_DOMAIN=$domain|" \
      -e "s|^ACME_EMAIL=.*|ACME_EMAIL=$email|" \
      -e "s|^COMMONVEIL_DIR=.*|COMMONVEIL_DIR=$(pwd)|" \
      -e "s|^UPDATER_TOKEN=.*|UPDATER_TOKEN=$token|" .env.example > .env.part
  chmod 600 .env.part
  mv .env.part .env
  echo "Wrote .env."
fi

docker compose pull
docker compose up -d

echo
echo "Commonveil is starting."
code=""
for _ in $(seq 1 60); do
  code=$(docker compose exec -T app node server/index.mjs setup-code 2>/dev/null || true)
  case "$code" in *-*-*) break ;; esac
  code=""
  sleep 2
done
site=$(grep '^SITE_DOMAIN=' .env | cut -d= -f2)
if [ -n "$code" ]; then
  echo "Open https://$site, choose Create an account, and enter this one-time setup code:"
  echo
  echo "    $code"
  echo
  echo "That account becomes the site's admin. The code works once. Until it's used, nobody else can sign up."
else
  echo "Open https://$site. If this is a new site, get its setup code with:"
  echo "    docker compose exec app node server/index.mjs setup-code"
fi
echo "Point DNS for that domain (and *.that-domain, for handles) at this server if you haven't yet."
