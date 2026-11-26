# Beacon Node.js Development Guide

This repository preserves the complete OpenTelemetry JavaScript Contrib source
and history and carries isolated Beacon-specific additions. The product and
cross-language documentation entry point is
[beacon-observability/beacon](https://github.com/beacon-observability/beacon).

## Status

The Beacon product version in this source tree is `3.0.0`. Its adopted
OpenTelemetry JavaScript Contrib commit is
`501b1e6b5640ba5003aeadba317c9d11b941e44e`; the exact baseline is recorded in
[upstream.lock.json](upstream.lock.json). It provides the three Beacon-owned
Node.js, profiling and Security packages. See the
[3.0.0 release notes](releases/3.0.0.md) for the source/dependency boundary and
the GitHub Release for publication receipts. Previous release acceptance is
retained in [the 2.0.0 validation record](validation/2.0.0.md).

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
- [Container distribution and Kubernetes injection](docker/nodejs/README.md)
- [Beacon Node.js 2.0.0 release acceptance](validation/2.0.0.md)
- [Beacon Node.js 1.3.1 release acceptance](validation/1.3.1.md)
- [Beacon Node.js 1.3.0 release acceptance](validation/1.3.0.md)
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

- follows the pinned Beacon Security schema v2 and fingerprint v1 contract in
  the public 2.0.0 packages; the previous 1.3.1 packages use schema v1;
- models bounded flows from selected HTTP inputs to SQL, command, outbound
  HTTP, and file sinks;
- publishes request findings and periodic runtime dependency inventories through
  OpenTelemetry Logs; current source uses compact v2 JSON Body with native event
  time, `event_id` log attributes and detection-time `span_id`;
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

## Current Security log binding

Current source pins Security specification
`d9d76e5a41d974d294bb596e06918bb954319bf6` and output profile
`beacon-security-log-body-v1`. Each OTel LogRecord Body is compact single-line v2
JSON. Only `observed_at` and `occurrence_id` move out of Body: event time uses the
native timestamp, and occurrence identity uses log attribute `event_id`.
`source` stays in Body and attributes. All remaining fields retain their original
paths; there is no SIEM envelope or `message` wrapper. Inventory IDs are computed
from the original logical event before compaction. Retransmissions retain time
and identity. Body byte budgets and multipart planning use the final UTF-8 JSON.
This source change does not establish acceptance for previously published releases.

Body-only diagnostic files omit event time and occurrence ID; retain native log
metadata separately when those values are required.
