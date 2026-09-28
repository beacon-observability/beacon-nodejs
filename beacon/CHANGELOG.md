# Beacon Node.js Changelog

This file records Beacon product changes. The root
[CHANGELOG.md](../CHANGELOG.md) remains the inherited upstream changelog, and
the exact adopted OpenTelemetry commit is recorded in
[`upstream.lock.json`](upstream.lock.json).

## Unreleased

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
