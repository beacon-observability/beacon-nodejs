# Beacon Node.js container image

The image distributes the three published Beacon Node.js packages and their locked production
dependencies on a pinned Node.js 24 / Debian bookworm glibc runtime. It contains no application.
Security and Profiling remain disabled unless explicitly enabled. It does not publish a new npm
package or rebuild the released Beacon JavaScript files.

The image is `ghcr.io/beacon-observability/beacon-nodejs:1.3.1`. Only the product version is tagged:
no `v`, runtime, architecture or packaging suffix, and no `latest` tag. Linux amd64 and arm64 share
one manifest list. A version tag must never be overwritten; pin the manifest digest in production.

## Runtime boundary

Use the bundled runtime, or copy the bundle into a compatible Node.js 24 Debian bookworm glibc
application image of the same architecture. Profiling includes native prebuilds: compatibility
with Alpine/musl, other Node.js major versions, other libc versions or architectures is not implied.
The npm package's wider runtime matrix is separate from this image's acceptance scope.

The image runs as `65532:65532`. `/opt/beacon-nodejs` contains the public packages, license files,
`package-lock.json`, original npm tarballs, release manifest and distribution provenance under
`metadata/`. No credentials or receiver endpoint are baked in. Preloading is configured by the
application rather than automatically applying to every command in the image.

## Application image

```dockerfile
FROM ghcr.io/beacon-observability/beacon-nodejs:1.3.1 AS beacon
FROM node:24-bookworm-slim
WORKDIR /srv/app
COPY --from=beacon /opt/beacon-nodejs /opt/beacon-nodejs
COPY . .
ENV NODE_OPTIONS="--import=/opt/beacon-nodejs/node_modules/@beacon-observability/nodejs/register.mjs"
USER 65532:65532
CMD ["node", "server.mjs"]
```

Install the application's own dependencies separately. Append the preload to existing `NODE_OPTIONS`.
Configure service identity and OTLP receivers at deployment time. Do not initialize another OTel SDK.
CommonJS tracing also supports `--require=/opt/beacon-nodejs/node_modules/@beacon-observability/nodejs/build/src/register.js`.
Security requires the ESM `--import` entry and explicit `BEACON_SECURITY_ENABLED=true` plus the
application source root; see the [package guide](../../../packages/nodejs/README.md).

## Kubernetes

The [initContainer example](init-container.yaml) copies the complete bundle to an `emptyDir`, then
the application mounts it read-only and sets the absolute preload path. It uses `fsGroup: 65532`
and non-root containers. Replace the application image and OTLP endpoint. No admission webhook,
cluster-wide installation or OpenTelemetry Operator compatibility is claimed.

## Build and publish

This is a separate manual distribution workflow after the stable npm and GitHub Release have
been accepted. Ordinary package builds do not publish a container image.

1. Update this directory's `package.json` to pin all three released Beacon packages to the same
   version and generate its production `package-lock.json` from the public npm registry. Commit and
   review that dependency lock before publication; do not silently re-resolve dependencies in CI.
2. Run **Beacon Node.js image** from `main` with the matching `X.Y.Z` input. Preparation verifies the
   stable source tag, all three public npm identities/integrities and the GitHub Release tarballs.
3. Native amd64 and arm64 candidates install the committed lock with dependency scripts disabled,
   then verify CommonJS and ESM preload, correlated OTLP traces, disabled optional features, native
   multipart profiles and opt-in Security SBOM delivery with non-root, read-only containers.
4. Approve the `beacon-release` environment. The publish job promotes those tested archives without
   rebuilding, rejects an existing version tag and publishes the single multi-platform tag.
5. The package administrator sets the package Public on first publication. Verify anonymous pulling
   and run the Kubernetes acceptance against the published digest. Future versions retain visibility.

PRs changing the image implementation also build/test both architectures; they never publish.
Publication uses `GITHUB_TOKEN` with package write permission and does not need an npm publish token.
Keep the environment approval configured. Interrupted untagged uploads can be retried; an existing
version tag must be verified or rolled back by digest, never overwritten.

Local build (Node.js, npm, GitHub CLI, Docker required):

```bash
node beacon/docker/nodejs/prepare.mjs 1.3.1 /tmp/beacon-nodejs-release
source=$(node -p 'require("/tmp/beacon-nodejs-release/provenance.json").source_commit')
docker buildx build --load -f beacon/docker/nodejs/Dockerfile \
  --build-arg BEACON_VERSION=1.3.1 --build-arg "BEACON_SOURCE_REVISION=$source" \
  -t beacon-nodejs-candidate /tmp/beacon-nodejs-release
bash beacon/docker/nodejs/verify-image.sh beacon-nodejs-candidate 1.3.1
```

The staging directory must be empty. For isolated cluster acceptance:

```bash
node beacon/docker/nodejs/kubernetes-smoke.mjs \
  YOUR_TEST_CONTEXT ghcr.io/beacon-observability/beacon-nodejs@sha256:REPLACE_ME 1.3.1
```

The script creates a unique temporary namespace, tests initContainer injection and actual local
receiver delivery, then deletes the namespace on success or failure. It does not change the current
kubectl context. `BEACON_K8S_NODE_IMAGE` can select a reachable equivalent of the pinned Node.js
fixture runtime. Cluster acceptance covers the architecture actually tested and does not establish
external backend compatibility or complete Security detection coverage.
