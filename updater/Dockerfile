# The Commonveil updater (updater/updater.mjs): Docker's command-line tools plus Node.js.
# Release images: ghcr.io/comutability/commonveil-updater
#
# Node comes from the official Node image (the 26.x LTS line, kept current by Node's own
# security releases), not from Alpine's package, which lags behind them. The Docker CLI and its
# Compose plugin are copied in from Docker's own image.
ARG DOCKER_IMAGE=docker:28.2.2-cli-alpine3.21
ARG NODE_IMAGE=node:26-alpine
FROM ${DOCKER_IMAGE} AS docker

FROM ${NODE_IMAGE}
# Alpine's security fixes published since the Node image was built. The minimum versions for
# fixes Snyk has reported are pinned too, so apk refuses to build an image without them:
# zlib 1.4-r0 (CVE-2026-4738).
RUN apk upgrade --no-cache && apk add --no-cache "zlib>=1.4-r0"
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
WORKDIR /updater
COPY updater.mjs ./
LABEL org.opencontainers.image.title="Commonveil updater" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/Comutability/commonveil-rebuild"
CMD ["node", "/updater/updater.mjs"]
