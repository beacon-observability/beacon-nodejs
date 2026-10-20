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

- Published the first `@beacon-observability/security-nodejs` package.
- Added bounded runtime observation for supported HTTP, SQL, command, outbound
  HTTP, and file boundaries.
- Added runtime SBOM events and the shared Beacon Security schema and
  fingerprint version 1 contract.
- Added Node.js 22 and 24 runtime validation and Kubernetes deployment
  guidance.
