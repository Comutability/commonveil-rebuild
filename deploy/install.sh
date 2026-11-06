#!/bin/sh
# Sets up Commonveil in this folder: asks for your domain, writes .env, and starts it.
#   curl -fsSLO https://raw.githubusercontent.com/Comutability/commonveil-rebuild/main/deploy/install.sh && sh install.sh
set -e
REPO="https://raw.githubusercontent.com/Comutability/commonveil-rebuild/main/deploy"

command -v docker >/dev/null 2>&1 || { echo "Install Docker first: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is needed (docker compose ...)."; exit 1; }

for f in docker-compose.yml Caddyfile .env.example; do
  [ -f "$f" ] || curl -fsSL "$REPO/$f" -o "$f"
done

if [ -f .env ]; then
  echo ".env already exists: starting with it."
else
  printf "Your site's domain (for example chat.example.com): "; read -r domain
  printf "Your email address (admin sign-in, and certificate notices): "; read -r email
  token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  sed -e "s|^SITE_DOMAIN=.*|SITE_DOMAIN=$domain|" \
      -e "s|^ACME_EMAIL=.*|ACME_EMAIL=$email|" \
      -e "s|^ADMIN_EMAILS=.*|ADMIN_EMAILS=$email|" \
      -e "s|^MAIL_FROM=.*|MAIL_FROM=Commonveil <no-reply@$domain>|" \
      -e "s|^COMMONVEIL_DIR=.*|COMMONVEIL_DIR=$(pwd)|" \
      -e "s|^UPDATER_TOKEN=.*|UPDATER_TOKEN=$token|" .env.example > .env
  chmod 600 .env
  echo "Wrote .env. Add SMTP_URL there later if you want email."
fi

docker compose pull
docker compose up -d
echo
echo "Commonveil is starting. In a minute, open https://$(grep '^SITE_DOMAIN=' .env | cut -d= -f2) and create your account."
echo "Point DNS for that domain (and *.that-domain, for handles) at this server if you haven't yet."
