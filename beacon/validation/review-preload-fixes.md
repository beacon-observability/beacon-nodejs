# Preload and profiler review fixes

Date: 2026-10-22. Baseline: `08cb44c3fe947d987aea9a7b2aa26cc198a9830a`.
These are unreleased changes to Beacon-owned entry points and profiling. The
inherited OTel register is retained unchanged.

## Scope

- #12: Beacon owns the zero-code SDK shutdown sequence: Security, profiler, SDK.
  A host-owned SDK must explicitly await Security shutdown before closing its
  LoggerProvider; independent processor shutdown callbacks do not establish an
  ordering guarantee.
- #22: A sole-owner SIGINT/SIGTERM allows bounded cleanup and restores signal
  termination. Application-owned handlers can drain requests before normal
  beforeExit cleanup and retain their exit policy.
- #23: The Security-disabled ESM preload installs IITM before application imports.
  Security continues to use its synchronous loader and compatibility checks.
- #24: Public API/preload imports do not load the native profiler. Requested
  native initialization failure is diagnosed without stopping application or
  tracing startup.
- #25: Background collection uses an unreferenced timer. Shutdown cancels an
  unfinished wall collection, repeated shutdown shares one promise, explicit
  collectOnce remains referenced, and overflowing intervals are rejected.
- #26: Profile identity honors OTEL_SERVICE_NAME precedence and decoded OTel
  service/version/environment/host resource attributes.

## Verification

```sh
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm run compile --workspace=@beacon-observability/nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/nodejs
node beacon/scripts/zero-code-smoke.mjs
node beacon/scripts/review-smoke.mjs
```

The packed regression script installs candidate tarballs rather than relying on
workspace TypeScript resolution. Real native collection does not retain an idle
process for a 60-second wall window. Injected package/native failures leave the
disabled path usable. A genuine ESM target emits one span with or without an
existing loader. Actual trace resources and multipart profile tags agree when
service.name exists only in OTEL_RESOURCE_ATTRIBUTES. Child processes verify the
first SIGINT, application-owned graceful draining, and an active Security finding
arriving through OTLP Logs before SIGTERM termination.

The local supported-runtime checks cover Node.js 22.22.3 and 24.16.0. The CI
workflow additionally validates the Node.js 18.19 and 20 entry/profiler paths;
Security collection remains restricted to its documented supported runtimes.
This evidence does not qualify an external collector or every native ABI.

## Delivery limits

Sole-owner signal cleanup has a 2.5-second deadline. Security's own timeout and
queue budgets still apply. Forced exit, repeated interrupt or an exhausted
deadline can lose records. Application process.exit calls bypass asynchronous
beforeExit work. An unfinished background wall sample is deliberately discarded
on shutdown; an export already in progress is awaited within the surrounding
lifecycle budget. No packages, tags or releases are published by this change.
