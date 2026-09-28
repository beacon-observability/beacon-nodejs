# Beacon Node.js Changelog

This file records Beacon product changes. The root
[CHANGELOG.md](../CHANGELOG.md) remains the inherited upstream changelog, and
the exact adopted OpenTelemetry commit is recorded in
[`upstream.lock.json`](upstream.lock.json).

## Unreleased

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
