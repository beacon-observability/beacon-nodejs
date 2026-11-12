# Beacon Node.js container image

The image distributes the three published Beacon Node.js packages and their locked production
dependencies on a pinned Node.js 24 / Debian bookworm glibc runtime. It contains no application.
Security and Profiling remain disabled unless explicitly enabled. It does not publish a new npm
package or rebuild the released Beacon JavaScript files.

The image is `ghcr.io/beacon-observability/beacon-nodejs:2.0.1`. Only the product version is tagged:
no `v`, runtime, architecture or packaging suffix, and no `latest` tag. Linux amd64 and arm64 share
one manifest list. A version tag must never be overwritten; pin the manifest digest in production.

## Runtime boundary

Use the bundled runtime, or copy the bundle into a compatible Node.js 24 Debian bookworm glibc
application image of the same architecture. Profiling includes native prebuilds: compatibility
with Alpine/musl, other Node.js major versions, other libc versions or architectures is not implied.
The npm package's wider runtime matrix is separate from this image's acceptance scope.
The bundle volume must allow native library mapping (no `noexec`); a read-only mount is supported.

The image runs as `65532:65532`. `/opt/beacon-nodejs` contains the public packages, license files,
`package-lock.json`, original npm tarballs, release manifest and distribution provenance under
`metadata/`. No credentials or receiver endpoint are baked in. Preloading is configured by the
application rather than automatically applying to every command in the image.

## Application image

```dockerfile
FROM ghcr.io/beacon-observability/beacon-nodejs:2.0.1 AS beacon
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

1. Run **Beacon Node.js image** from `main` with the existing stable `X.Y.Z` input.
   No source files, dependency locks, workflow defaults, or examples need updating
   for a routine version release.
2. One preparation job verifies the source tag, public npm identities/integrities
   and GitHub Release tarballs. It generates the three exact package pins and one
   production `package-lock.json`, then archives the Dockerfile and build context.
3. Native amd64 and arm64 candidates consume the same checksummed snapshot with
   dependency scripts disabled. They verify CommonJS/ESM preload, correlated OTLP
   traces, disabled optional features, native profiles and opt-in
   Security SBOM delivery with non-root, read-only containers.
4. Review the snapshot and results, then approve the `beacon-release` environment.
   The publish job promotes those tested archives without rebuilding, rejects an
   existing version tag and publishes the single multi-platform tag.
5. On first publication, the package administrator sets the package Public. Verify
   anonymous pulling and Kubernetes acceptance against the published digest.

The preparation job's build-context artifact is retained for 90 days, including
its SHA-256 checksum, generated dependency lock, original public Beacon packages,
Dockerfile and provenance. Rerunning failed candidate jobs uses that artifact;
rerunning all jobs also reuses an existing unexpired snapshot from the same run.
A new workflow run resolves a new snapshot, so specifying the same product version
alone does not promise identical transitive dependencies. For a later rebuild,
download and verify the retained snapshot instead of resolving again. The final
image also preserves the dependency lock and public Beacon artifacts. PR smoke
versions and installation examples are fixed fixtures, not a moving release selector.
Change the image implementation through PRs when packaging, runtime or validation
needs change.

PRs changing the image implementation also build/test both architectures; they never publish.
Publication uses `GITHUB_TOKEN` with package write permission and does not need an npm publish token.
Keep the environment approval configured. Interrupted untagged uploads can be retried; an existing
version tag must be verified or rolled back by digest, never overwritten.

Local build (Node.js, npm, GitHub CLI, Docker required):

```bash
node beacon/docker/nodejs/prepare.mjs 2.0.1 /tmp/beacon-nodejs-release
source=$(node -p 'require("/tmp/beacon-nodejs-release/provenance.json").source_commit')
docker buildx build --load -f /tmp/beacon-nodejs-release/Dockerfile \
  --build-arg BEACON_VERSION=2.0.1 --build-arg "BEACON_SOURCE_REVISION=$source" \
  -t beacon-nodejs-candidate /tmp/beacon-nodejs-release
bash beacon/docker/nodejs/verify-image.sh beacon-nodejs-candidate 2.0.1
```

The staging directory must be empty. For isolated cluster acceptance:

```bash
node beacon/docker/nodejs/kubernetes-smoke.mjs \
  YOUR_TEST_CONTEXT ghcr.io/beacon-observability/beacon-nodejs@sha256:REPLACE_ME 2.0.1
```

The script creates a unique temporary namespace, tests initContainer injection and actual local
receiver delivery, then deletes the namespace on success or failure. It does not change the current
kubectl context. `BEACON_K8S_NODE_IMAGE` can select a reachable equivalent of the pinned Node.js
fixture runtime. Cluster acceptance covers the architecture actually tested and does not establish
external backend compatibility or complete Security detection coverage.

The image smoke selects the profiling wire contract from the exporter API in the
installed candidate. Published releases with multipart profiling retain their
original acceptance protocol; candidates exposing `OtlpProfilingExporter` are
checked with OTLP/HTTP. This is a test-fixture distinction and does not restore
legacy exporters in the current profiler package.
