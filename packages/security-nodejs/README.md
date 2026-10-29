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

## License

Apache 2.0

## Security telemetry v2

Security exports only `beacon.security.finding` and
`beacon.security.sbom.inventory` through OpenTelemetry Logs. The pinned shared
contract is schema v2 and fingerprint v1. A finding is emitted for each matched
request, deduplicated by fingerprint within that request. Its stable `finding_id`
groups the issue; its `occurrence_id` identifies this request. Trace and span
context belongs to this occurrence. Missing trace context does not suppress a
finding, and a trace ID does not guarantee that a backend retained the trace.

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
