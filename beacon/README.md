# Beacon Node.js Development Guide

This repository preserves the complete OpenTelemetry JavaScript Contrib source
and history and carries isolated Beacon-specific additions. The product and
cross-language documentation entry point is
[beacon-observability/beacon](https://github.com/beacon-observability/beacon).

## Status

Beacon Node.js `1.1.0` provides the public
`@beacon-observability/nodejs` zero-code package and the matching
`@beacon-observability/profiler-nodejs` component on npm. Beacon Security is
implemented for the next release but has not yet been published. The repository is
based on the official upstream `main` commit recorded when the project was
established. That exact commit, rather than the moving branch name, is the
reproducible baseline.

The dedicated Beacon checks target Node.js 18.19, 20, 22, and 24. The complete
upstream matrix and receiver compatibility matrix have not been run. Only the
three Beacon-owned packages are in this repository's publication scope;
inherited upstream packages retain their own publication lifecycle.

## Repository Layout

| Location | Purpose |
| --- | --- |
| [`packages/`](../packages/) | Inherited OpenTelemetry JavaScript Contrib packages and Beacon-specific packages |
| [`packages/nodejs/`](../packages/nodejs/) | Public Beacon zero-code auto-instrumentation package |
| [`packages/profiler-nodejs/`](../packages/profiler-nodejs/) | Experimental Beacon Node.js profiling bridge |
| [`packages/security-nodejs/`](../packages/security-nodejs/) | Opt-in Beacon Security runtime and runtime SBOM |
| [`examples/zero-code-demo/`](../examples/zero-code-demo/) | Application with no telemetry imports used by the zero-code smoke test |
| [`examples/validation-demo/`](../examples/validation-demo/) | Local OTLP trace validation example |
| [`beacon/`](./) | Beacon baseline, synchronization, status, and release documentation |
| [`.github/workflows/beacon-ci.yml`](../.github/workflows/beacon-ci.yml) | Isolated Beacon validation workflow |
| [`.github/workflows/`](../.github/workflows/) | Inherited automation, disabled in the Beacon repository |

## Maintenance Entry Points

- [Pinned upstream baseline](upstream.lock.json)
- [Upstream synchronization](UPSTREAM.md)
- [Beacon changelog](CHANGELOG.md)
- [CI and repository checks](CI.md)
- [Verified Beacon-specific contributors](CONTRIBUTORS.md)
- [Product version](version.properties)
- [Release prerequisites](RELEASING.md)
- [Beacon Node.js package documentation](../packages/nodejs/README.md)
- [Profiler package documentation](../packages/profiler-nodejs/README.md)
- [Security package documentation](../packages/security-nodejs/README.md)

Development occurs on `main`. Upstream names, package layout, and licenses are
retained. Beacon-specific capabilities should remain isolated instead of
renaming inherited packages across the monorepo.

## Current Beacon-Specific Source

The Beacon-owned `@beacon-observability/nodejs` package:

- provides `@beacon-observability/nodejs/register` for `NODE_OPTIONS` preload;
- starts standard OpenTelemetry Node.js auto-instrumentation before application
  modules load;
- uses standard `OTEL_*` environment configuration; and
- starts the Beacon profiler when `OTEL_PROFILING_ENABLED=true`.

The Beacon Security workspace:

- follows the pinned Beacon Security schema and fingerprint v1 contract;
- models bounded flows from selected HTTP inputs to SQL, command, outbound
  HTTP, and file sinks;
- publishes findings and runtime SBOM snapshots through OpenTelemetry Logs;
- remains disabled by default and does not enable local files implicitly; and
- requires Node.js 22.22.3+ or 24.11.1+ when enabled.

The experimental `@beacon-observability/profiler-nodejs` workspace package:

- collects Node.js wall and heap profiles through `@datadog/pprof`;
- maps OpenTelemetry resource attributes to profiling tags;
- produces receiver-compatible `pprof` attachments; and
- can send multipart profile batches to a configured profiling endpoint.

This list identifies the public package entry points. Receiver compatibility
still depends on the configured endpoint accepting the documented multipart
`pprof` layout.

## Local Validation

Run commands from the repository root unless noted otherwise:

```sh
npm ci
node beacon/scripts/check-project.mjs
npm run compile --workspace=@beacon-observability/nodejs
npm test --workspace=@beacon-observability/nodejs
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
node --test packages/security-nodejs/tests/schema-contract.test.mjs
# Full Security runtime tests require Node.js 22.22.3+ or 24.11.1+.
npm test --workspace=@beacon-observability/security-nodejs
node beacon/scripts/zero-code-smoke.mjs
```

Full upstream validation requires the matrices and services documented by the
upstream project. Passing the profiler package tests alone does not validate the
complete repository or an ingestion backend.
