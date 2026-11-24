# `@beacon-observability/security-nodejs`

Beacon Security is the opt-in runtime security capability used by the complete
Beacon Node.js package. It records bounded modeled data-flow observations and a
runtime dependency inventory. Findings are observations or candidate risks, not
confirmed vulnerabilities.

Applications normally install and preload `@beacon-observability/nodejs`
instead of loading this component directly. Security requires Node.js 22.22.3+
or 24.11.1+ because its scoped source transformation uses synchronous module
hooks.

```bash
npm install @beacon-observability/nodejs

export NODE_OPTIONS="--import @beacon-observability/nodejs/register"
export BEACON_SECURITY_ENABLED=true
export BEACON_SECURITY_NODE_INCLUDE=/srv/app
export OTEL_SERVICE_NAME=orders
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
node /srv/app/server.mjs
```

Security is disabled by default. Runtime SBOM is enabled only as part of an
enabled Security lifecycle and can be disabled with
`BEACON_SECURITY_SBOM_ENABLED=false`. Local files are also disabled by default;
set `BEACON_SECURITY_LOCAL_OUTPUT_ENABLED=true` for diagnostic snapshots.

For Kubernetes, install the complete `@beacon-observability/nodejs` package in
the application image and use the checked-in
[Deployment example](examples/kubernetes/deployment.yaml). No Security sidecar
or init container is required; the normal application container only needs the
ESM preload and OTLP environment variables.

The language-neutral contract is pinned in
[`security-spec.properties`](security-spec.properties). This implementation
currently models selected HTTP inputs and SQL, command, outbound HTTP, and file
sinks. It transforms only application files under
`BEACON_SECURITY_NODE_INCLUDE`; `node_modules`, Node built-ins, and explicitly
excluded roots are not transformed.

## Request coverage and unknown calls

Business success and zero delivery drops do not establish complete Security
analysis. `requests_incomplete` counts requests with at least one coverage gap;
it is independent of `requests_started`, `requests_completed`, and delivery
loss. Reconcile counter deltas per worker before aggregating cluster workers.

`unmodeled_call_result` means a call returned a non-null value while its receiver
or arguments carried tracked provenance, but no model or transformed function
accounted for that result. It does not by itself identify the responsible library.
Number's `isFinite`, `isInteger`, `isNaN`, and `isSafeInteger` predicates preserve
provenance on their boolean results. Checking a number does not sanitize the
original value or guarantee that subsequent calls are modeled.

Redis is not a modeled Security adapter. In particular, a Redis `GET` with a
request-derived key can produce `unmodeled_call_result`. Neither the key's taint
nor the absence of a finding establishes the provenance or safety of the stored
value. Node HTTP event callbacks and Promises are not categorically unsupported;
coverage depends on the calls and data crossing their boundaries.

To locate an unknown call, temporarily set
`BEACON_SECURITY_CALL_DIAGNOSTICS_ENABLED=true` and enable the host OpenTelemetry
diagnostic logger at warning level (for the Beacon preload, `OTEL_LOG_LEVEL=warn`).
The diagnostic contains only the static transformed source location, including
the file path and line/column, encoded as a JSON string. It does not inspect or
log function names, arguments, return values, or request identifiers. Each process
records at most 32 distinct locations, once each, with each location capped at
1024 characters. Diagnostics are disabled by default, create no files, and do
not change incomplete accounting. Restart the process to reset the location
budget. Restrict diagnostic log access because source paths can reveal code
layout.

See [the issue #37 validation record](../../beacon/validation/issue-37.md) for the
reduced mixed-workload regression and its limits. The original frozen 1.3.1 K6
workload must be rerun before claiming its coverage or normal Security overhead
has been validated.

## License

Apache 2.0

## Security SIEM output

Security exports only `beacon.security.finding` and
`beacon.security.sbom.inventory` through OpenTelemetry Logs. The pinned shared
contract is schema v2 and fingerprint v1. A finding is emitted for each matched
request, deduplicated by fingerprint within that request. Its stable `finding_id`
groups the issue; its `occurrence_id` identifies this request. Trace and span
context belongs to this occurrence. Missing trace context does not suppress a
finding, and a trace ID does not guarantee that a backend retained the trace.

Current source exports the `beacon-security-siem-v1` envelope on both the OTel
Logs route and optional evidence JSONL stream. The fifteen required string
fields are `time`, `event_id`, `event_class`, `source`, `service`, `tenant_id`,
`actor`, `ip`, `action`, `target`, `target_type`, `outcome`, `status`, `severity`,
and `message`. `instance_id` is also retained. `message` is the exact serialized
v2 evidence after sampling and declared truncation; consumers must parse it
for `event_name`, `occurrence_id`, `observed_at`, dependencies, and detailed
flow evidence. No legacy format switch or duplicate event is emitted.

Available trace correlation uses `trace_id`, `span_id`, and integer
`trace_flags` in both the envelope and evidence. `span_id` identifies the span
active at detection, including when it is the HTTP server span. The LogRecord
associates with that same invocation span. If none is active, no span is
substituted. `server_span_id` and `current_span_id` are absent from output.

`service` uses the configured OTel `service.name`. `tenant_id` uses an explicitly
configured `tenant.id` in `OTEL_RESOURCE_ATTRIBUTES`, otherwise `default`.
This runtime has no verified principal or trusted proxy enrichment, so `actor`
and `ip` are empty. Request headers never supply tenant identity. A receiving
system must enforce tenant isolation; `default` is only an unspecified identity.
Findings always use `outcome=unknown`, `status=info`, and
`severity=informational`, irrespective of attack evidence or HTTP status.
Inventory uses `outcome=success` for local collection only.

Finding `event_id` is the occurrence ID and `target` is its stable finding ID.
Inventory IDs are deterministic SHA-256 IDs over the contract's ordered JSON
identity tuple, including collection time and part index. Inventory target is
the process instance. Retransmissions retain IDs; later rounds and distinct
parts do not collide. Fingerprint v1 is unchanged.

Record and rate byte budgets include the final serialized envelope, escaped
`message`, configured service/tenant values, and trace fields. Findings that
exceed the record limit retain the existing explicit evidence truncation
markers inside `message`; if even the reduced envelope cannot fit, it is
rejected with delivery-loss accounting. Inventory planning budgets escaped
bytes and rejects an unrepresentable dependency instead of omitting it.
`message` preserves the evidence Body, not the complete OTLP transport record.

This source change follows the exact contract revision recorded in
`security-spec.properties`; previously released 2.0.x packages retain their
original v2 Body until upgraded. It is a consumer-visible wire-format change.

`BEACON_SECURITY_FINDINGS_SAMPLE_SECONDS` (default `300`) controls full evidence
sampling independently of occurrence delivery and trace sampling. A sampled-out
occurrence still carries its identity, rule, attack-evidence status, sink,
request, and available correlation. It sets `evidence_sampled=false`, retains
the omission reason, and omits empty evidence arrays. Sampling alone does not
set `truncated=true`; that flag describes actual collection or byte truncation.
The `collection_complete` boolean records known collection gaps. Stronger
evidence may upgrade a request's retained occurrence without changing its ID.

The online finding excludes duplicate Resource maps, fixed placeholders,
`evidence_id`, and process-local `occurrences_total`. A resolved `component`
directly carries name, version, and an optional real artifact hash. Findings
without a resolved component remain reportable. Consumers aggregate received
occurrence IDs by finding ID; delivery is best effort and cannot reconstruct
records lost to a full queue or byte budget.

The inventory publishes loaded library dependencies after initial asynchronous
collection and every `BEACON_SECURITY_SBOM_REFRESH_SECONDS` (default `300`),
even when unchanged. Successful empty dependencies are valid. A failed
collection sends no replacement, so consumers retain the last complete result.
Large results use `part_index` and `part_count` only when fragmented; consumers
replace a list only after all parts for an instance and `observed_at` arrive.
Each inventory includes process `started_at` and collection-time `uptime_ms`.
Local CycloneDX output is opt-in and retains only the current document, without
an SBOM history file. The optional local findings and run snapshots retain
debug aggregates; default production mode keeps bounded sampling state only.

## Request-specific attack evidence

A finding's `attack_evidence` status is `unknown` for unsupported or imprecise
analysis, `no_evidence` when supported analysis finds no exploitation evidence,
or `suspected` when tainted input controls supported syntax. Reasons are bounded
machine-readable values without captured request data. An invocation, normal
return, or HTTP status cannot establish
successful exploitation. `no_evidence` is not a safety verdict.

Set `BEACON_SECURITY_ANALYSIS_SQL_DIALECT=ansi` to enable the bounded ANSI lexical
subset; the default is `unknown`. It supports single/double quoted strings and
identifiers, doubled SQL quotes, numeric literals, and simple SQL operators and
comments. This is not a SQL parser or complete dialect implementation. Other
dialects, backslash/dollar quoting, unsupported syntax, imprecise ranges, and
inputs exceeding 8192 UTF-16 code units or 64 marks retain uncertainty. Fixed SQL
parameter binding remains separate from untrusted dynamic templates.

The shell subset supports simple POSIX `sh`, `bash`, `dash`, `ksh`, and `zsh`
commands, quoting, escapes, and control separators. Expansion, redirection,
compound syntax, and other shells remain `unknown`. Executable control requires
policy; ordinary argv and fixed-destination path/query input remain separate
observations. Network allowlist and filesystem-root policies are not implemented,
so related boundary decisions remain `unknown`. Normalization alone does not
prove safety. Byte strings are not interpreted as a known textual dialect.

Within a request, `suspected > unknown > no_evidence` selects the retained
occurrence without changing its ID or counting it twice. Stronger evidence
bypasses ordinary detail sampling. Each later request retains its own status;
a weaker request cannot replace a stronger representative.
When local diagnostic output is enabled, `attack_evidence_counts` partitions
process-local request occurrences by the three statuses, and
`strongest_attack_evidence` describes the strongest retained status. These
local counters do not represent confirmed attacks or exploit successes.

### Exporting findings without attack evidence

Findings with `attack_evidence.status=no_evidence` are excluded from OpenTelemetry Logs and
the evidence JSONL stream by default. Set `BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED=true`
to include them. `unknown` and `suspected` remain eligible for export, and SBOM inventories
are unaffected. Filtering happens before queue admission and is not counted as export loss.
Detection, request deduplication, and stronger evidence upgrades still run; optional local
finding snapshots and span summaries can retain observations excluded from event export.
This changes the previous default, which exported all three statuses. `no_evidence` remains
a classification, not a safety verdict.
