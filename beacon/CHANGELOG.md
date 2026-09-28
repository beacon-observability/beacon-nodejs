# Beacon Node.js Changelog

This file records Beacon product changes. The root
[CHANGELOG.md](../CHANGELOG.md) remains the inherited upstream changelog, and
the exact adopted OpenTelemetry commit is recorded in
[`upstream.lock.json`](upstream.lock.json).

## Unreleased

### Initial downstream project

- Established the Beacon Node.js repository from official OpenTelemetry
  JavaScript Contrib `main` commit
  `31b2af9dd5fcc5f96949e5666f8f45b30b997722`, preserving its complete history.
- Added the private experimental
  `@beacon-observability/profiler-nodejs` workspace and local validation
  examples.
- Verified profiler compilation and six unit tests on Node.js 24 during the
  initial import.
- Added pinned source metadata, an independent Beacon development version,
  project checks, and isolated Beacon CI.

### Known limitations

- The complete upstream and Node.js runtime matrices have not yet passed in the
  Beacon repository.
- DataKit ingestion and release-candidate artifacts have not been accepted.
- The profiler package is private and there is no official Beacon Node.js
  release or installation entry.
