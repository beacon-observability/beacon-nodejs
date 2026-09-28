<!-- markdownlint-disable MD007 MD034 -->
# Changelog

## Unreleased

## 1.1.0 - Unreleased

- Added integration with the `@beacon-observability/nodejs` zero-code preload
  package.
- Kept the standalone profiler API and multipart `pprof` format unchanged.
- Updated the emitted `profiler_version` resource tag to `1.1.0`.

## 1.0.0 - 2026-09-28

- Published the first public npm package.
- Exposed wall and heap profile collection through `NodeProfiling`.
- Exposed receiver-neutral multipart export through `HttpProfilingExporter`.
- Validated Node.js 18.19, 20, 22, and 24 in Beacon CI.

## 0.1.0 - 2026-09-28

- Added the initial private Beacon profiling package.
- Added wall and heap profile collection with a receiver-neutral HTTP exporter.
- Kept the package private while receiver and package publication validation
  remain in progress.
