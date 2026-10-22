# Runtime SBOM review fixes

Date: 2026-10-22. Baseline: `08cb44c3fe947d987aea9a7b2aa26cc198a9830a`.
This is unreleased development evidence for the bounded runtime inventory.

## Scope

- #27: Cached discovery plus unchanged observation/build inputs bypass component
  cloning, mapping, serialization and hashing. Default health heartbeat is 60
  seconds, configurable with BEACON_SECURITY_SBOM_HEALTH_SECONDS; failures and
  actual changes remain visible. Loader bursts coalesce with a 100ms minimum
  publication interval. Explicit refresh and close still publish pending input.
- #28: Loaded-component membership is separate from the bounded URL cache.
  Eviction does not imply unload. A bounded package-root map preserves component
  attribution after a particular file URL is evicted. Removing a loaded module's
  disk file retains observed process membership and reports unreadability.
- #29: Service-only npm workspace selectors discover matching ancestor workspace
  locks and hoisted node_modules without changing the business transform scope.
- #30: Top-level/nested/scoped lock keys retain declared npm identities; absent
  optional packages remain declarations and .bin/.cache are not scanned as
  failed package directories.

## Verification

```sh
node --test packages/security-nodejs/tests/sbom.test.mjs packages/security-nodejs/tests/sbom-regressions.test.mjs
```

The regression suite crosses the actual default 4,096-observation cap using
real file URLs, verifies retained loaded identity and resolution, and reports the
URL-cache loss separately. Workspace fixtures select only apps/api and observe a
scoped dependency hoisted to the root. Declared-but-uninstalled optional identity
and tooling-directory health are checked in the full local CycloneDX document.
An unchanged worker running multiple one-second checks emits no new full map or
per-check health; explicit refresh still emits current health. Existing nested
package/symlink, failed-publication retry, history and shutdown tests remain.

## Operational limits

Full discovery still refreshes within the configured cache period, and the
periodic check can invalidate it when root metadata changes. pnpm/PnP support is
not invented by the workspace change. Component, entry, scan-byte, URL and root
mapping limits remain bounded with incomplete-coverage reasons. Short-lived
processes can exhaust a shutdown deadline before a large scan completes.

Correct workspace discovery can materially increase startup CPU and RSS because
the old implementation omitted hoisted packages. The representative monorepo
fixture changes from four discovered components to approximately 2,748; therefore
memory comparisons are also coverage comparisons. Three alternating measured
trials used the same dependencies, Node.js 24.16.0, 200 requests, concurrency eight
and fresh per-trial output directories, after an excluded warm-up per runtime.
The candidate combined all three review-fix groups.

| Mode | Baseline startup ms | Candidate startup ms | Baseline RSS MiB | Candidate RSS MiB | Baseline req/s | Candidate req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SBOM, business transform off | 505 | 526 | 164.1 | 208.9 | 1412 | 1416 |
| Full | 806 | 841 | 211.0 | 284.8 | 381 | 500 |

Values are medians. One short SBOM-only trial ended while health still reported
initializing; the other SBOM trials and every full candidate trial exposed the
larger graph. These measurements do not imply complete runtime dependency
discovery or a production sizing guarantee.


## Equal-coverage worker observation

A separate Node.js 24.16.0 probe selected the same repository root for both
runtimes, so both inventories contained 2,748 components. It fed 1,024 real URL
query variants in batches of 64 every 25ms, then observed 6.2 idle seconds. The
refresh check was accelerated to one second; discovery caching stayed at 300
seconds. These are single-run diagnostics, not throughput medians.

| Observation | Baseline | Candidate |
| --- | ---: | ---: |
| Initial publication, ms | 1334 | 1234 |
| Startup/burst worker CPU, ms | 1962 | 1684 |
| Startup/burst publications | 4 | 5 |
| Main publication handler total, ms | 1.47 | 5.77 |
| Idle worker CPU, ms | 604.14 | 8.82 |
| Idle full publications | 0 | 0 |
| Idle health events | 6 | 0 |

Worker CPU came from Worker.cpuUsage(). Main handler timing wrapped only
synchronous published-message dispatch, including map freezing; structured-clone
transport is excluded, so it is not total main-thread copy cost. The extra
package-root attribution map increases this handler's work. Publication count is
arrival/scan dependent and did not decrease in this run; coalescing bounds the
minimum publication interval rather than promising a fixed count. The unchanged
worker avoids the previous repeated content work even when neither runtime
publishes a changed map. Normal heartbeat remains 60 seconds.
