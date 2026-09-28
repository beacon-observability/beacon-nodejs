# Beacon Node.js Development Guide

This repository preserves the complete OpenTelemetry JavaScript Contrib source
and history and carries isolated Beacon-specific additions. The product and
cross-language documentation entry point is
[beacon-observability/beacon](https://github.com/beacon-observability/beacon).

## Status

Beacon Node.js `0.1.0` is a GitHub source release. The repository is based on
the official upstream `main` commit recorded when the project was established.
That exact commit, rather than the moving branch name, is the reproducible
baseline.

The dedicated Beacon checks pass on Node.js 18.19, 20, 22, and 24. The complete
upstream matrix and receiver compatibility matrix have not been run. The
Beacon-specific profiler remains private and experimental, and no package in
this repository is published as a supported Beacon npm distribution.

## Repository Layout

| Location | Purpose |
| --- | --- |
| [`packages/`](../packages/) | Inherited OpenTelemetry JavaScript Contrib packages and Beacon-specific packages |
| [`packages/profiler-nodejs/`](../packages/profiler-nodejs/) | Experimental Beacon Node.js profiling bridge |
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
- [Profiler package documentation](../packages/profiler-nodejs/README.md)

Development occurs on `main`. Upstream names, package layout, and licenses are
retained. Beacon-specific capabilities should remain isolated instead of
renaming inherited packages across the monorepo.

## Current Beacon-Specific Source

The experimental `@beacon-observability/profiler-nodejs` workspace package:

- collects Node.js wall and heap profiles through `@datadog/pprof`;
- maps OpenTelemetry resource attributes to profiling tags;
- produces receiver-compatible `pprof` attachments; and
- can send multipart profile batches to a configured profiling endpoint.

This list identifies source entry points, not stable package capabilities. The
package remains private until its public package identity and receiver
compatibility have been validated.

## Local Validation

Run commands from the repository root unless noted otherwise:

```sh
npm ci
node beacon/scripts/check-project.mjs
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
```

Full upstream validation requires the matrices and services documented by the
upstream project. Passing the profiler package tests alone does not validate the
complete repository or an ingestion backend.
