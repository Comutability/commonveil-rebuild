# The Commonveil updater (rust/commonveil-updater): one small program and Docker's command-line
# tools, which it uses to install a release. Release images: ghcr.io/comutability/commonveil-updater
#   docker build -t commonveil-updater -f updater/Dockerfile .      (from the repository's root)
#
# The Docker CLI and its Compose plugin are copied in from Docker's own image.
ARG DOCKER_IMAGE=docker:28.2.2-cli-alpine3.21
# Rust builds the updater (1.88 or later), on each platform for that platform.
ARG RUST_IMAGE=rust:1-alpine
ARG ALPINE_IMAGE=alpine:3
FROM ${DOCKER_IMAGE} AS docker

FROM ${RUST_IMAGE} AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /build/rust
# Dependencies first (their sources, exactly as locked); the workspace's other member (the
# server) needs its manifest.
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/commonveil-server/Cargo.toml ./commonveil-server/
COPY rust/commonveil-updater/Cargo.toml ./commonveil-updater/
RUN mkdir -p commonveil-server/src commonveil-updater/src \
 && echo 'fn main() {}' > commonveil-server/src/main.rs && touch commonveil-server/src/lib.rs \
 && echo 'fn main() {}' > commonveil-updater/src/main.rs \
 && cargo fetch --locked
COPY rust/commonveil-updater ./commonveil-updater
RUN cargo build --release --locked -p commonveil-updater \
 && cp target/release/commonveil-updater /commonveil-updater

FROM ${ALPINE_IMAGE}
# Alpine's security fixes published since the base image was built. The minimum versions for
# fixes Snyk has reported are pinned too, so apk refuses to build an image without them:
# zlib 1.4-r0 (CVE-2026-4738).
RUN apk upgrade --no-cache && apk add --no-cache "zlib>=1.4-r0"
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=build /commonveil-updater /usr/local/bin/commonveil-updater
WORKDIR /updater
LABEL org.opencontainers.image.title="Commonveil updater" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/Comutability/commonveil-rebuild"
EXPOSE 8090
CMD ["commonveil-updater"]
