<!-- markdownlint-disable MD007 MD034 -->
# Changelog

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
- Added clean-tarball zero-code validation for OTLP trace and multipart
  profile
  export.
