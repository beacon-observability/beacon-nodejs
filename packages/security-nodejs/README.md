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
