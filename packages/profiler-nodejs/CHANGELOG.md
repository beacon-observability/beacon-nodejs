<!-- markdownlint-disable MD007 MD034 -->
# Changelog

## Unreleased

## 2.0.0 - 2026-10-30

- Release the matching profiling component and update the emitted
  `profiler_version` resource tag to `2.0.0`. Profiling behavior is unchanged.

## 1.3.1 - 2026-10-22

- Load the native backend on demand and isolate optional initialization failure.
- Use unreferenced background wall timers, cancel unfinished samples on shutdown,
  and reject overflowing intervals while retaining explicit collection behavior.
- Honor decoded standard OTel service identity with explicit option precedence.
- Update the emitted profiler_version tag to 1.3.1.

## 1.3.0 - 2026-10-20

- Release the matching profiling component for Beacon Node.js 1.3.0 and update
  the emitted `profiler_version` resource tag.

## 1.2.0 - 2026-10-03

- Released with the matching Beacon Node.js product and Security component;
  profiling behavior remains unchanged from `1.1.0`.

## 1.1.0 - 2026-09-28

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
- Added wall and heap profile collection with a receiver-neutral HTTP
  exporter.
- Kept the package private while receiver and package publication validation
  remain in progress.
