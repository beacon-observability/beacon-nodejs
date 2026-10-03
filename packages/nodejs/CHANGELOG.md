<!-- markdownlint-disable MD007 MD034 -->
# Changelog

## Unreleased

## 1.2.0 - 2026-10-03

- Added the opt-in Beacon Security runtime and runtime SBOM through the ESM
  `register` preload entry point.
- Kept Security disabled by default and local diagnostic output explicitly
  opt-in.
- Added a Kubernetes Deployment example using the complete Beacon Node.js
  package without a Security sidecar or init container.

## 1.1.0 - 2026-09-28

- Published the first `@beacon-observability/nodejs` product package.
- Added zero-code Node.js auto-instrumentation through the `register` preload
  entry point and standard OpenTelemetry environment variables.
- Added opt-in Beacon profiling controlled entirely through environment
  variables.
- Added clean-tarball zero-code validation for OTLP trace and multipart profile
  export.
