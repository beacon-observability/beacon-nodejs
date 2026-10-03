# Node.js QA harness

The harness exercises the observable contract of the Node.js package. It uses
only the Node standard library for orchestration and runs the application in a
child process with the package preload and an OpenTelemetry bootstrap.

The matrix is six cases per runtime: Express 4, Express 5, and Fastify 5 in
both ESM and CommonJS. `run-matrix.mjs` writes one JSON result per case and a
`summary.json`. A missing package, missing framework alias, or missing OTel
dependency is reported as `blocked`; it is never reported as a pass.

The application fixture checks original values and exception behavior, one
getter evaluation, recursive closure execution, same-request Promise
concurrency, ESM live-binding/cycle behavior, cross-request trace isolation,
local fs access, a controlled child process, and one local HTTP target with
its exact path/query. `/flow/:flowId` additionally drives positive and
constant/bound negative controls from query, route-parameter, header, and JSON
body inputs through Promise propagation to fs, child-process, local HTTP, and
SQL call sites; its result checks require evidence source/role and server
trace-id correlation. PostgreSQL
and MySQL bind checks run when `BEACON_SECURITY_QA_PG_URL` or
`BEACON_SECURITY_QA_MYSQL_URL` is supplied; otherwise their result is explicitly
skipped.

The focused transform check seeds a `SecurityState` with `capture`, runs both
ESM and CommonJS transformed fixtures through `bind(state, ...)`, and asserts
marks after Promise constructor/resolve/then/all, call/apply/bind, a getter,
a closure, and two concurrent request states. It also verifies a real
`fs.promises.readFile` sink event:

```sh
node tests/taint-smoke.mjs
```

Run from `nodejs/` after the package dependencies are installed:

```sh
BEACON_SECURITY_QA_RESULTS_DIR=/tmp/beacon_security-nodejs-qa-results \
  node tests/run-matrix.mjs --node-line 24.11.1
node tests/verify-results.mjs /tmp/beacon_security-nodejs-qa-results
node tests/check-api-contract.mjs
```

For the four-mode performance comparison, fix the load parameters and run:

```sh
BEACON_SECURITY_QA_PERF_REQUESTS=200 BEACON_SECURITY_QA_PERF_CONCURRENCY=8 \
  BEACON_SECURITY_QA_RESULTS_DIR=/tmp/beacon_security-nodejs-perf \
  node tests/performance/run.mjs
```

The report contains startup time, throughput, P95 latency, event-loop delay,
RSS, cleanup state, and an explicit unavailable value when the package does
not expose a drop counter.

The runner expects the package export
`@beacon-observability/security-nodejs/register`, the package root export
`SecurityInstrumentation`, and the framework package aliases configured by
the package's `package.json`. Override an alias with
`BEACON_SECURITY_QA_EXPRESS4_PACKAGE`, `BEACON_SECURITY_QA_EXPRESS5_PACKAGE`, or
`BEACON_SECURITY_QA_FASTIFY5_PACKAGE` when the root package uses a different alias.
