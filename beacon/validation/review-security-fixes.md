# Security runtime review fixes

Date: 2026-10-22. Baseline: `08cb44c3fe947d987aea9a7b2aa26cc198a9830a`.
This is unreleased development evidence, not a package publication or a claim of
complete application, dialect, or third-party sink coverage.

## Scope

| Issues | Resulting behavior |
| --- | --- |
| #10 | Eligible inactive functions avoid expression boxing; expression checks reuse an enablement snapshot while API/pause controls remain live. |
| #11 | Default error stacks recover business callers without replacing application formatters or permanently changing stack limits. |
| #13 | Passive response error monitoring preserves unhandled errors and cleans up completion listeners. |
| #14 | Bounded queue priority, event/byte reservations and loss-class counters protect stronger evidence under ordinary occurrence pressure. |
| #15 | String and JSON models retain exact or explicitly conservative provenance, including replacement callbacks and call/apply/bind. |
| #16 | Fastify abort cleanup continues the callback chain exactly once. |
| #17 | Equivalent Express query snapshots share bounded metadata with copy-on-write mutation isolation. |
| #18 | Completed responses/requests cannot acquire another Security state. |
| #19 | Explicit shell options respect combined flags, option operands and script boundaries. |
| #20 | ANSI quoted data and tainted quote boundaries are analyzed in their actual lexical context. |
| #21 | SQL whitespace runs have a deterministic linear operation bound. |
| #31 | File sinks use symlink destination operands and classify numeric open modes correctly. |

## Verification

The focused regression files cover actual transformed functions, real Express 5
and Fastify servers, same-request mutation isolation, default/custom stacks,
Unicode expansion and callback side effects. A real OTLP HTTP receiver verifies
stronger evidence after ordinary capacity exhaustion. Event and byte budget tests
remain bounded and ordinary occurrence identities are not coalesced.

Run the existing suite and the added regression files on Node.js 22.22.3+ and
24.11.1+:

```sh
node beacon/scripts/check-project.mjs
npm test --workspace=@beacon-observability/security-nodejs
npm run test:conformance --workspace=@beacon-observability/security-nodejs
```

Default unsupported shell expansions/redirection and unsupported SQL dialects
remain unknown. Conservative normalization marks preserve code-risk findings;
they do not establish an attack or successful exploitation. The bounded query
cache charges weak aliases to tracked bytes and is cleared with request state.
Application-owned stack formatters and custom name/message accessors retain their
own behavior rather than being globally overridden.

## Performance observations

The deterministic inactive-path test executes 1,000 eligible function calls with
zero boxed-expression helper calls; an asynchronous continuation test verifies
the same inactive path and request-bound taint after await. The live-request test performs 10,000
`current()` checks without another environment read and verifies pause/resume and
refreshed admission configuration. SQL input near the 8,192 UTF-16 limit stays
within a linear regexp-operation bound.

The four-mode HTTP fixture compares the exact baseline runtime with this
candidate using the same dependencies, 200 requests and concurrency 8. Each
trial has its own output directory; warm-up trials are excluded and measured
trials alternate baseline/candidate. Short synthetic runs are measurements, not
production overhead guarantees. Medians from three measured trials on Node.js
24.16.0 are below. This candidate combines the three review-fix groups; the table
does not isolate each PR's contribution.

| Mode | Baseline req/s | Candidate req/s | Baseline p95 ms | Candidate p95 ms | Baseline startup ms | Candidate startup ms | Baseline RSS MiB | Candidate RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| OTel only | 2663 | 2595 | 5.37 | 6.39 | 268 | 270 | 96.6 | 96.3 |
| Security, SBOM off | 549 | 752 | 20.26 | 14.04 | 629 | 646 | 187.8 | 183.6 |
| SBOM, business transform off | 1412 | 1416 | 11.49 | 10.37 | 505 | 526 | 164.1 | 208.9 |
| Full | 381 | 500 | 24.52 | 21.35 | 806 | 841 | 211.0 | 284.8 |

Baseline runtime files were checked byte-for-byte against the baseline archive.
The candidate source digest stayed unchanged throughout warm-up and measured
runs. OTel-only results expose ordinary host variance. The corrected workspace
inventory discovers approximately 2,748 components where the old service-only
selector found four; increased SBOM/full RSS includes that larger graph. One
short SBOM-only trial ended before its health snapshot exposed a component
count. Request counts and per-second budget boundaries are too small/variable
to use these runs as delivery-loss comparisons; the actual OTLP priority tests
provide that deterministic evidence instead.
