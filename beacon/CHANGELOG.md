# Beacon Node.js Changelog

This file records Beacon product changes. The root
[CHANGELOG.md](../CHANGELOG.md) remains the inherited upstream changelog, and
the exact adopted OpenTelemetry commit is recorded in
[`upstream.lock.json`](upstream.lock.json).

## Unreleased

## 1.3.0 - 2026-10-20

- Export a request-specific finding occurrence and trace/span correlation
  independently of detailed-evidence sampling, including when local
  aggregation is full.
- Add request-specific attack evidence, bounded opt-in ANSI SQL and POSIX
  shell analysis, and conservative unknown states for unsupported syntax or
  missing policies.
- Preserve same-request occurrence identity during evidence upgrades, retain
  the strongest representative, and expose evidence-status request counts
  without inferring exploit success.
- Retain schema version 1, fingerprint version 1, default-disabled Security,
  and bounded export queues and byte budgets.

## 1.2.0 - 2026-10-03

### Opt-in Security

- Added `@beacon-observability/security-nodejs` and integrated it with the
  `@beacon-observability/nodejs/register` ESM preload entry point.
- Added bounded runtime data-flow findings and runtime SBOM events following
  the pinned Beacon Security schema and fingerprint version 1 contract.
- Kept Security and diagnostic file output disabled by default, with explicit
  `BEACON_SECURITY_*` configuration for application source scope and local
  snapshots.
- Added contract, loader, framework boundary, exporter, control, and SBOM
  regression tests for the supported Node.js 22 and 24 runtimes.

## 1.1.0 - 2026-09-28

### Zero-code Node.js package

- Added the `@beacon-observability/nodejs` product package with a
  `@beacon-observability/nodejs/register` preload entry point.
- Added zero-code startup through `NODE_OPTIONS` with standard OpenTelemetry
  environment configuration and automatic Node.js instrumentation.
- Integrated opt-in wall and heap profiling through the matching
  `@beacon-observability/profiler-nodejs` component.
- Added an unchanged HTTP application and release smoke test that verify OTLP
  HTTP trace export and compatible multipart profile export.
- Kept inherited OpenTelemetry packages outside the Beacon publication scope.

### Known limitations

- The zero-code release smoke test covers CommonJS preload through
  `NODE_OPTIONS=--require`; it does not claim complete ESM loader coverage.
- The profiler layout and receiver limitations documented for 1.0.0 still
  apply.

## 1.0.0 - 2026-09-28

### Public npm release

- Published `@beacon-observability/profiler-nodejs` as the first public Beacon
  Node.js npm package.
- Kept inherited OpenTelemetry packages outside the Beacon publication scope.
- Validated project metadata, clean dependency installation, profiler
  compilation, six unit tests, package contents, and the declared Node.js CI
  matrix.

### Known limitations

- The profiler exports the documented compatible multipart `pprof` layout and
  is not an implementation of the OpenTelemetry Profiles signal.
- Receiver compatibility depends on the configured profiling endpoint.
- The complete inherited upstream test matrix is outside this release scope.

## 0.1.0 - 2026-09-28

### Initial downstream project

- Established the Beacon Node.js repository from official OpenTelemetry
  JavaScript Contrib `main` commit
  `31b2af9dd5fcc5f96949e5666f8f45b30b997722`, preserving its complete history.
- Added the private experimental
  `@beacon-observability/profiler-nodejs` workspace and local validation
  examples.
- Added a receiver-neutral HTTP profiling exporter and local validation
  examples.
- Verified the Beacon checks on Node.js 18.19, 20, 22, and 24, including
  profiler compilation and six unit tests.
- Added pinned source metadata, an independent Beacon product version, project
  checks, and isolated Beacon CI.

### Known limitations

- The complete inherited upstream matrix has not been run in the Beacon
  repository.
- Receiver compatibility and install-from-artifact acceptance have not been
  completed.
- The profiler package remains private and experimental; this release does not
  publish an npm package.
