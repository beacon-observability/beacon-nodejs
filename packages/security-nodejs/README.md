# `@beacon-observability/security-nodejs`

Beacon Security is the opt-in runtime security capability used by the complete
Beacon Node.js package. It records bounded modeled data-flow observations and a
runtime dependency snapshot. Findings are observations or candidate risks, not
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

## Finding occurrences and evidence sampling

Security exports one `beacon.security.finding` per finding fingerprint per request.
Requests share a stable `finding_id` but retain distinct `evidence_id` values
(aliased as `occurrence_id`) and their own trace/span context. Same-request
repeated detections count once. Requests without a trace are still exported;
a trace ID does not guarantee that the backend retained that trace.

`BEACON_SECURITY_FINDINGS_SAMPLE_SECONDS` (default `300`) controls full-evidence
sampling, independently of occurrence delivery and trace sampling. Lightweight
occurrences retain identity, sink, request context, and correlation with
`evidence_sampled=false`, `evidence_sample_reason=interval`, and empty `sources`,
`propagation`, `ranges`, and `stack` arrays. They declare `truncated=true` and
`truncation_reason=evidence_sampled_out`; empty arrays do not mean absence of taint.

`occurrences_total` is a process-local per-finding request count. If the
aggregation table is full, bounded occurrence delivery continues with
`aggregation_status=capacity_exceeded` and no total; tracked findings use
`aggregation_status=tracked`. A representative snapshot may describe an earlier
request than `last_trace_id`. Queue, rate, and byte limits remain in effect,
health counters expose loss, and tiny byte budgets can produce
`beacon.security.export.truncated` envelopes. Occurrence logs can increase
volume and do not provide durable delivery.

## Request-specific attack evidence


A finding's code-risk `assessment` and `validation=unvalidated` are independent
of `attack_evidence`. Its status is `unknown` for unsupported or imprecise
analysis, `no_evidence` when supported analysis finds no exploitation evidence,
or `suspected` when tainted input controls supported syntax. Reasons are bounded
machine-readable values without captured request data. `outcome=not_assessed`
remains explicit: an invocation, normal return, or HTTP status cannot establish
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
`attack_evidence_counts` partitions process-local request occurrences by the
three statuses, and `strongest_attack_evidence` describes the strongest retained
status. These counters do not represent confirmed attacks or exploit successes.

## Runtime and delivery safeguards

Common string trimming, case conversion, replacement, splitting, padding, and
JSON data flows retain bounded provenance. Trimming, ASCII case changes and simple string splits
retain exact UTF-16 ranges; Unicode case expansion, replacement, regular-expression splits,
and JSON conversions use conservative ranges when an exact mapping was not
observed. Replacement/replacer/reviver callbacks run once with their original
business arguments. Custom serialization and accessor boundaries remain explicit
coverage gaps. Normalization is not a sanitizer or a safety verdict.

Eligible synchronous and asynchronous functions use their original expressions
when no live request context exists. AsyncLocalStorage retains that absence across
await continuations. Escaping closures, dynamic scope and writes to enclosing
bindings retain instrumentation. Paused request contexts also
retain instrumentation because collection can resume. Per-expression enablement
checks reuse an environment snapshot; environment changes are refreshed at
request admission, loader checks and control ticks. API enable/disable, loader
compatibility and pause state remain live.

Default Error stacks retain business caller depth without installing a global
`Error.prepareStackTrace` hook. Application formatters, custom name/message
accessors and explicitly assigned stacks remain under application control. Request
completion observes response errors through `errorMonitor`, preserving otherwise
unhandled errors, and completed requests cannot acquire a new state.

Equivalent bounded Express query snapshots can share immutable tracking records.
Writes detach the record before changing its marks. `max.objects` counts distinct
tracking records; each additional weak object alias is charged to the request's
tracked-byte budget, and snapshot caches are cleared at request completion.

The Security export queue prioritizes suspected evidence above diagnostics and
ordinary occurrences. Higher-priority records can evict queued lower-priority
records. By default, 10 percent of the event and byte budgets is reserved for
suspected evidence; `BEACON_SECURITY_EXPORT_PRIORITY_RESERVED_PERCENT` accepts
0 through 50. Event reservations round down, so very small event limits may
reserve zero events. Loss diagnostics retain their existing budget exception.
Loss counters identify ordinary, diagnostic and suspected records, and priority
evictions have a separate counter. Total limits remain bounded, ordinary
occurrences keep their distinct identities, and stronger evidence can still be
dropped when its capacity is exhausted. Delivery remains best effort.

When using a host-owned SDK, call and await Security `shutdown()` before shutting
down the host LoggerProvider/SDK. Forced process termination and exhausted
shutdown deadlines can still lose records.
