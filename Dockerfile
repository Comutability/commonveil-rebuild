# Commonveil, self-hosted: one image with the site and its server. See docs/SELF_HOSTING.md.
#   docker build -t commonveil .
# Release images are built by .github/workflows/release.yml as ghcr.io/comutability/commonveil.

# The Node.js base image. Override only to test with a local base.
ARG NODE_IMAGE=node:24-alpine

# ---- Build the site (the browser app), for a self-hosted server ----
FROM ${NODE_IMAGE} AS site
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
ARG COMMONVEIL_VERSION=""
ENV VITE_COMMONVEIL_BACKEND=selfhost COMMONVEIL_VERSION=${COMMONVEIL_VERSION}
RUN npx vite build --outDir /build/dist-selfhost && node scripts/check-bundle.mjs /build/dist-selfhost

# ---- Only what the server needs at run time ----
FROM ${NODE_IMAGE} AS deps
WORKDIR /deps
COPY package.json ./
RUN node -e 'const p=require("./package.json");const d=p.dependencies;require("fs").writeFileSync("server-package.json",JSON.stringify({name:"commonveil-server",private:true,type:"module",dependencies:{ws:d.ws,nodemailer:d.nodemailer,"@simplewebauthn/server":d["@simplewebauthn/server"]}}))' \
 && mv server-package.json package.json && npm install --omit=dev --no-audit --no-fund

FROM ${NODE_IMAGE}
ARG COMMONVEIL_VERSION=""
LABEL org.opencontainers.image.title="Commonveil" \
      org.opencontainers.image.description="End-to-end encrypted chat and communities you can run yourself" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/Comutability/commonveil-rebuild"
WORKDIR /app
ENV NODE_ENV=production DATA_DIR=/data DIST_DIR=/app/dist PORT=8080 NODE_NO_WARNINGS=1
COPY --from=deps /deps/node_modules ./node_modules
COPY package.json ./
COPY server ./server
COPY base44/shared ./base44/shared
COPY base44/actors ./base44/actors
COPY base44/entities ./base44/entities
COPY src/lib/site/releases.js ./src/lib/site/releases.js
COPY csp.config.mjs ./
COPY --from=site /build/dist-selfhost ./dist
RUN mkdir -p /data && chown node:node /data \
 && if [ -n "$COMMONVEIL_VERSION" ]; then sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$COMMONVEIL_VERSION\"/" package.json; fi
USER node
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/api/health >/dev/null || exit 1
CMD ["node", "server/index.mjs"]
