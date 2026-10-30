# CI and Repository Checks

[`Beacon Node.js CI`](../.github/workflows/beacon-ci.yml) is the maintained
validation entry for pushes to `main`, pull requests targeting `main`, and
manual runs. It is restricted to `beacon-observability/beacon-nodejs` and uses
read-only repository permissions.

## Beacon Matrix

The workflow runs the Beacon project check, installs the committed lockfile,
compiles and tests all Beacon-owned packages, and runs the zero-code injection
smoke test on Node.js 18.19, 20, 22, and 24. The Node.js 24 job also checks
repository formatting, Markdown, release-please package metadata, and example
lockfiles.

This matrix validates the Beacon-specific workspace only. It does not replace
the complete upstream instrumentation, browser, service-integration, or
all-versions matrices and does not establish production support for every
runtime in the matrix.

Upstream build tools run on Node.js 24. Each matrix job then selects its declared
Node.js runtime before running Beacon tests. Jobs switching runtime reinstall the
locked dependencies with `npm ci` so native modules use the test runtime ABI.

Beacon-owned Mocha packages select their explicit ts-node runner and retain all
test files, coverage, and the 10-second timeout. They bypass the inherited global
Mocha config, whose upstream resolution hook requires Node.js 22 or newer.

## Inherited Workflow Isolation

All inherited OpenTelemetry workflows are disabled in the Beacon GitHub
repository. Only the Beacon workflow may be enabled after review. Upstream
release, dependency-update, scheduled, issue-management, and organization-
specific workflows are not Beacon publication or maintenance entry points.

The separately reviewed [Beacon Node.js image workflow](../.github/workflows/beacon-image.yml)
is also a Beacon-owned entry point. It tests distribution changes on native
amd64/arm64 PR runners and publishes only when manually dispatched from `main`,
after `beacon-release` approval. See the [container guide](docker/nodejs/README.md).

After every upstream synchronization, review newly added or renamed workflow
files before enabling any Actions event. Repository conditions and missing
secrets are not substitutes for disabling an unadapted publication workflow.

## Required Local Checks

Run from the repository root:

```sh
node beacon/scripts/check-project.mjs
npm ci
npm run compile --workspace=@beacon-observability/nodejs
npm test --workspace=@beacon-observability/nodejs
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
npm run test:conformance --workspace=@beacon-observability/security-nodejs
# Full Security tests require Node.js 22.22.3+ or 24.11.1+.
npm test --workspace=@beacon-observability/security-nodejs
node beacon/scripts/zero-code-smoke.mjs
node beacon/scripts/review-smoke.mjs
npm run lint:prettier
npm run lint:markdown
npm run lint:release-please
```

The self-contained smoke test uses an ephemeral HTTP port by default. CI sets
`BEACON_ZERO_CODE_RECEIVER_PORT=9529` to verify the requested fixed HTTP port.
To exercise an existing local OTLP/gRPC receiver, run:

```sh
BEACON_ZERO_CODE_EXTERNAL_ENDPOINT=http://127.0.0.1:4317 \
BEACON_ZERO_CODE_EXTERNAL_PROTOCOL=grpc \
node beacon/scripts/zero-code-smoke.mjs
```

Passing CI produces development evidence only. It does not publish artifacts or
replace runtime, ingestion, performance, upgrade, or rollback acceptance.

## Preload and termination regression checks

`beacon/scripts/review-smoke.mjs` builds and installs the three candidate tarballs
in an isolated application. It verifies lazy native loading and failure isolation,
short-lived native profiling, native ESM instrumentation with and without an
existing loader, resource identity correlation, and signal handling. On supported
Security runtimes it also terminates an active request and checks actual OTLP Logs
delivery before SDK shutdown. All receivers are local ephemeral HTTP servers.
The workflow runs this check across the Beacon Node matrix; unsupported Security
runtimes run the remaining preload/profiler checks.
