# Changelog

## 2.0.0 - 2026-10-30

- Adopt Beacon Security event schema v2 while retaining fingerprint v1.
  Export only request findings and periodic dependency inventories through
  OpenTelemetry Logs; remove health, summary, loss, and failure events.
- Replace the dual occurrence identifiers with `occurrence_id`, remove online
  cumulative counts and duplicate Resource fields, and retain evidence and
  correlation when sampling omits detail.
- Publish each successful inventory every 300 seconds by default, including
  unchanged or valid empty lists. Failed collection leaves the last list
  intact; large lists carry only necessary fragment fields.
- Keep full finding representatives and local aggregates only when diagnostic
  output is enabled. Stop writing SBOM history and retaining online revisions.

## 1.3.1 - 2026-10-22

- Skip full unchanged SBOM publication work, lower default health heartbeat to
  60 seconds, and coalesce observation bursts with bounded publication delay.
- Retain bounded loaded-component membership independently of URL-cache eviction
  and preserve package attribution through a bounded package-root map.
- Discover hoisted npm workspace dependencies separately from business roots;
  retain top-level/scoped lock identities and skip dot tooling directories.
- Preserve existing scan and coverage limits. Larger corrected inventories can
  consume more memory; unsupported package managers remain explicitly uncertain.

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
