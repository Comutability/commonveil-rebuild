# Commonveil, self-hosted: one image with the site and its server. See docs/SELF_HOSTING.md.
#   docker build -t commonveil .
# Release images are built by .github/workflows/release.yml as ghcr.io/comutability/commonveil.
#
# The server is the Rust one (rust/commonveil-server): one static program, with nothing else
# installed beside it. Node.js only builds the site (the browser app) and isn't in the image
# that runs.

# Base images; override only to test with a local base.
# Node.js builds the site: the 26.x LTS line, which has the fixes from Node's October 2026
# security release (26.12.1 and later).
ARG NODE_IMAGE=node:26-alpine
# Rust builds the server (1.88 or later). It's built for each platform on that platform (arm64
# under emulation in the release workflow), so both builds run the same steps.
ARG RUST_IMAGE=rust:1-alpine
# The image that runs.
ARG ALPINE_IMAGE=alpine:3

# ---- Build the site (the browser app), for a self-hosted server ----
FROM ${NODE_IMAGE} AS site
WORKDIR /build
# The install policy (.npmrc) comes first, so it applies to the install.
COPY .npmrc package.json package-lock.json ./
# Base44's packages are only for the Base44-hosted build: a self-hosted build removes them, and
# check-independent.mjs (below) fails the build if anything of theirs is still needed.
RUN npm ci --no-audit --no-fund && rm -rf node_modules/@base44
COPY . .
ARG COMMONVEIL_VERSION=""
ENV VITE_COMMONVEIL_BACKEND=selfhost COMMONVEIL_VERSION=${COMMONVEIL_VERSION}
RUN npx vite build --outDir /build/dist-selfhost && node scripts/check-bundle.mjs /build/dist-selfhost && node scripts/check-independent.mjs /build/dist-selfhost

# ---- Build the server: one static program (musl) ----
FROM ${RUST_IMAGE} AS server
RUN apk add --no-cache musl-dev gcc
WORKDIR /build/rust
# Dependencies first (their sources, exactly as locked), so builds that only change Commonveil's
# own code don't fetch them again. The workspace's other members (the updater and the client
# core) need their manifests.
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/commonveil-server/Cargo.toml ./commonveil-server/
COPY rust/commonveil-updater/Cargo.toml ./commonveil-updater/
COPY rust/commonveil-client/Cargo.toml ./commonveil-client/
RUN mkdir -p commonveil-server/src commonveil-updater/src commonveil-client/src \
 && echo 'fn main() {}' > commonveil-server/src/main.rs && touch commonveil-server/src/lib.rs \
 && echo 'fn main() {}' > commonveil-updater/src/main.rs && touch commonveil-client/src/lib.rs \
 && cargo fetch --locked
COPY rust/commonveil-server ./commonveil-server
RUN cargo build --release --locked -p commonveil-server \
 && cp target/release/commonveil-server /commonveil-server \
 && DATA_DIR=/tmp/check /commonveil-server version >/dev/null

FROM ${ALPINE_IMAGE}
# Alpine's security fixes published since the base image was built. The minimum versions for
# fixes Snyk has reported are pinned too, so apk refuses to build an image without them:
# zlib 1.4-r0 (CVE-2026-4738).
# The server runs as user 1000, the same id as the Node.js image's `node` user, so an existing
# site's data stays readable after the update.
RUN apk upgrade --no-cache && apk add --no-cache "zlib>=1.4-r0" \
 && addgroup -g 1000 commonveil && adduser -D -H -u 1000 -G commonveil -h /app -s /sbin/nologin commonveil
ARG COMMONVEIL_VERSION=""
# Every release image identifies the exact pinned Secure Net source revision.
# The migration staging service still defaults to disabled in the Rust server.
ARG SECURE_NET_REV="not-specified"
LABEL org.opencontainers.image.secure-net.commit="${SECURE_NET_REV}" \
      org.opencontainers.image.secure-net.transfer="experimental-disabled-by-default"
LABEL org.opencontainers.image.title="Commonveil" \
      org.opencontainers.image.description="End-to-end encrypted chat and communities you can run yourself" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/Comutability/commonveil-rebuild"
WORKDIR /app
ENV APP_ROOT=/app DATA_DIR=/data DIST_DIR=/app/dist ENTITIES_DIR=/app/entities PORT=8080
COPY --from=server /commonveil-server /usr/local/bin/commonveil-server
# package.json gives the site its version; entities are the data model the server enforces.
COPY package.json ./
COPY base44/entities ./entities
COPY --from=site /build/dist-selfhost ./dist
RUN mkdir -p /data && chown commonveil:commonveil /data \
 && if [ -n "$COMMONVEIL_VERSION" ]; then sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$COMMONVEIL_VERSION\"/" package.json; fi
USER commonveil
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/api/health >/dev/null || exit 1
CMD ["commonveil-server"]
