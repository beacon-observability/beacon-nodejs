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

Current source exports compact single-line v2 JSON directly as the OTel Logs
Body and optional evidence JSONL. `observed_at` moves to native event time and
`occurrence_id` moves to log attribute `event_id`; other fields retain their
original paths. `source` remains in both Body and attributes. Consumers parse Body
once, with no SIEM envelope or `message` wrapper. Trace correlation uses
`trace_id`, `span_id`, and integer `trace_flags`. `span_id` identifies the span
active at detection; absent context is never fabricated.

Inventory IDs retain the deterministic SHA-256 algorithm over the original
logical event's collection time and part index. Retransmissions retain time and
identity. Record and rate byte budgets and inventory partitioning use final UTF-8
Body bytes. Findings retain explicit truncation flags when evidence must be
reduced. If the reduced Body cannot fit, export records delivery loss. Inventory
rejects an unrepresentable dependency instead of silently omitting it.

This follows the revision in `security-spec.properties`. The wire format differs
from the SIEM envelopes in 3.0.0 and the complete v2 events in 2.0.x. Body-only
diagnostic archives omit event time and occurrence ID; use OTel metadata when
those values are required. Service and tenant configuration remain Resource
attributes; no service or runtime maps are added to Body.

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

## Current Security log binding

Current source pins Security specification
`d9d76e5a41d974d294bb596e06918bb954319bf6` and output profile
`beacon-security-log-body-v1`. Each OTel LogRecord Body is compact single-line v2
JSON. Only `observed_at` and `occurrence_id` move out of Body: event time uses the
native timestamp, and occurrence identity uses log attribute `event_id`.
`source` stays in Body and attributes. All remaining fields retain their original
paths; there is no SIEM envelope or `message` wrapper. Inventory IDs are computed
from the original logical event before compaction. Retransmissions retain time
and identity. Body byte budgets and multipart planning use the final UTF-8 JSON.
This source change does not establish acceptance for previously published releases.

Body-only diagnostic files omit event time and occurrence ID; retain native log
metadata separately when those values are required.
