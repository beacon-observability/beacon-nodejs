# Security SIEM v1 source validation

This records source validation, not a published release or production backend
acceptance. The implementation was updated from Node.js main baseline
`3f5c4a46` against Security contract commit
`4a30f30e1027568cfbcf8661079a072fc89bd825`.
The output profile is `beacon-security-siem-v1`, with embedded event schema 2
and unchanged fingerprint version 1. Released 2.0.x artifacts are unchanged.

## Validated behavior

- All seven shared SIEM vectors match their exact expected envelopes. Original
  serialized messages retain whitespace, escapes, Unicode, and member order.
- Shared fingerprint vectors remain unchanged. Findings retain unknown outcome
  regardless of attack evidence; no-evidence filtering still precedes admission
  to OTel and JSONL export queues.
- Detection retains the active invocation span, including the request-entry
  span. When none is active, no server span is substituted. Evidence and the
  envelope omit both legacy span field names, and the LogRecord associates
  with the invocation span.
- Service and configured tenant Resource values enter the envelope before
  compacting evidence. No verified principal or trusted proxy enrichment is
  implemented: actor and IP remain empty. Tenant fallback is `default`.
- Escaped envelope bytes determine record/rate budgets and inventory splits.
  Multipart tests preserve all dependencies exactly once and distinguish part
  IDs while keeping retransmission IDs stable. Sampling and declared evidence
  truncation remain visible inside `message`.
- A real HTTP request through the Security preload and Express/HTTP
  instrumentation triggered a file-read finding, exported by the OTel Logs
  SDK over OTLP/HTTP to Collector Contrib `0.135.0`. The Collector file passed
  both SIEM and embedded v2 schemas, source/INFO checks, and equality of the
  envelope, evidence, and OTLP invocation span. Export counters reported one
  emitted record and zero drops.

## Checks

Node.js `24.22.1`:

```sh
node beacon/scripts/check-project.mjs
node --test --test-concurrency=1 'packages/security-nodejs/tests/*.test.mjs'
node --test packages/security-nodejs/tests/span-correlation.test.mjs
npm run test:conformance --workspace=@beacon-observability/security-nodejs
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm run compile --workspace=@beacon-observability/nodejs
npm test --workspace=@beacon-observability/nodejs
npm run lint:prettier
npm run lint:markdown
```

The Security suite passed 124 tests before the three focused detection-span
cases were added; those three cases also passed. Conformance passed 14 tests
and the Node.js package passed eight tests. An initial concurrent run during
dependency installation exceeded two existing test deadlines; the serial run
passed without relaxing their timeouts.

Node.js `22.22.3` also passed 26 focused checks across schema conformance,
SIEM vectors and byte budgets, detection span correlation, and exporter/runtime
controls. Repository metadata, Prettier, Markdown, and diff-whitespace checks
passed.

The Collector check can be repeated with the integration fixtures in
`packages/security-nodejs/tests/integration/collector/`; `verify-siem.mjs`
validates the actual Collector JSONL output rather than application stdout.
Collector receipt does not establish downstream storage or full OTLP archival.

## Consumer migration

Parse the OTel Body as a SIEM envelope and then parse `message` for detailed
v2 evidence and inventory assembly. Use top-level occurrence/inventory
`event_id`, `instance_id`, and available trace fields for correlation. Do not
expect `dependencies`, `event_name`, or `schema_version` at the envelope top
level. No compatibility format switch, duplicate route, tag, or release was
introduced by this source change.
