# The Commonveil updater (updater/updater.mjs): Docker's command-line tools plus Node.js.
# Release images: ghcr.io/comutability/commonveil-updater
ARG DOCKER_IMAGE=docker:27-cli
FROM ${DOCKER_IMAGE}
RUN apk add --no-cache nodejs
WORKDIR /updater
COPY updater.mjs ./
LABEL org.opencontainers.image.title="Commonveil updater" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/Comutability/commonveil-rebuild"
CMD ["node", "/updater/updater.mjs"]
