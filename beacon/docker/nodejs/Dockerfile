FROM node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS dependencies
WORKDIR /opt/beacon-nodejs
COPY package.json package-lock.json ./
# Published packages include native prebuilds. Never execute dependency install scripts.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/ \
    && npm cache clean --force
COPY assets/ metadata/release/
COPY provenance.json metadata/provenance.json
RUN chmod -R a+rX,a-w /opt/beacon-nodejs

FROM node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
ARG BEACON_VERSION
ARG BEACON_SOURCE_REVISION
LABEL org.opencontainers.image.title="Beacon Node.js" \
      org.opencontainers.image.source="https://github.com/beacon-observability/beacon-nodejs" \
      org.opencontainers.image.version="${BEACON_VERSION}" \
      org.opencontainers.image.revision="${BEACON_SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Published Beacon Node.js packages and locked dependencies on Node.js 24, Debian glibc"
COPY --from=dependencies /opt/beacon-nodejs /opt/beacon-nodejs
USER 65532:65532
WORKDIR /tmp
CMD ["node"]
