# Security unknown-call coverage investigation (#37)

## Scope

Issue [#37](https://github.com/beacon-observability/beacon-nodejs/issues/37)
reports incomplete coverage in a frozen 1.3.1 Express/PG/Redis/HTTP benchmark.
Its full benchmark fixture and per-request evidence are not included in the
issue. The checked-in regression is a new reduction of the documented recipe,
not a reproduction of that benchmark's exact 20% distribution or a performance
qualification. The comparison starts from the current 3.0.0 source baseline.

## Findings and implementation

- A tracked query value converted with `Number()` and then passed to
  `Number.isInteger()` produced `unmodeled_call_result` before the fix. The
  native predicate was not registered as a propagation model. The four strict
  Number predicates now preserve input provenance on their boolean result
  without repeating conversion or removing provenance from the original input.
- The issue's fixed-response Node HTTP callback/Promise helper did not produce
  this gap when exercised without the unmodeled numeric predicate. This does
  not establish that all HTTP helpers or callback APIs preserve provenance.
- Redis is not a modeled Security adapter. In the reduction, Redis `GET` with
  a request-derived key continues to report a gap. Its returned stored value
  is not assigned the request key's provenance. The unsupported boundary is
  retained explicitly rather than suppressed to make counters look complete.
- Opt-in diagnostics identify the static source location of remaining unknown
  calls through the host OTel diagnostic logger. They never inspect the callee
  name, arguments, result, or request data. Logs are capped at 32 locations per
  process and 1024 characters per location; duplicate locations are suppressed.
  Logger failure does not alter business behavior or incomplete accounting.

## Regression and acceptance boundary

`packages/security-nodejs/tests/integration/mixed-workload.test.mjs` runs four
actual Node cluster workers with Security disabled and enabled, tracing sampled off, and
profiling/SBOM disabled. The application source is loaded through the synchronous
Security preload transformer. It verifies original responses, invalid numeric
input behavior, concurrent request counters, delivery-loss and queue-drop
counters, and exact gap counts by fixture route. The workspace's
`test:mixed-workload` script is the dedicated test entry point. Beacon CI runs
it after the unit tests on Node.js 22 and 24 so cluster
startup does not compete with the unit suite's bounded subprocess tests.

The default HTTP-only case sends 20 business requests plus one deliberate
unknown-call control and one invalid-input control per worker. With the original
predicate model absent, all 22 requests were marked incomplete. After the fix,
only the unknown-call control is incomplete; started/completed counts are 22
and active requests are zero for each worker.

The service case uses real PostgreSQL, Redis clients and fixed HTTP responses.
Its 100 business requests per worker follow the documented 40/25/15/15/5 mix
of HTTP/DB/cache/downstream/waterfall. The same two controls bring the count to
102 per worker. After the fix, 21 requests per worker are incomplete: 15 cache,
5 waterfall, and the deliberately unknown call. The other paths do not produce
coverage gaps. All requests have their expected business result and each worker's
started/completed counts reconcile. This distribution differs from the historical
issue and must not be presented as its root cause.

Validation used Node.js 22.22.3 and 24.22.1, Express 5.2.1, PostgreSQL 16.15
and Redis 6.2.6 with the Redis 5.11.0 client. On Node.js 24.22.1 the final
default Security suite passed all 129 tests. On Node.js 22.22.3 the adapter,
diagnostic and real-service cluster regressions passed all 16 tests. Logs
exporters are disabled in this focused harness;
zero local delivery-loss/drop counters do not establish backend delivery. Existing
exporter and OTLP integration tests remain responsible for their own contracts.
No production receiver or original K6 performance window is qualified here.

To run the optional service case, provide isolated test services and run from
the repository root:

```sh
BEACON_SECURITY_QA_PG_URL=postgresql://qa:qa@127.0.0.1:5432/qa \
BEACON_SECURITY_QA_REDIS_URL=redis://127.0.0.1:6379 \
node --test packages/security-nodejs/tests/integration/mixed-workload.test.mjs
```

The fixture writes the fixed key `beacon-issue37:7` to the supplied Redis
instance; use disposable QA services. Without both service URLs the service
case is explicitly skipped, while the four-worker HTTP regression still runs.

Issue closure still requires retesting the original fixture or an agreed
equivalent, locating its remaining gaps with the bounded diagnostics, and
confirming that supported paths are modeled or unsupported boundaries are
explicitly accepted. Do not infer normal Security overhead from incomplete
performance windows.
