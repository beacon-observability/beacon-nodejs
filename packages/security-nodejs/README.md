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

The language-neutral contract is pinned in
[`security-spec.properties`](security-spec.properties). This implementation
currently models selected HTTP inputs and SQL, command, outbound HTTP, and file
sinks. It transforms only application files under
`BEACON_SECURITY_NODE_INCLUDE`; `node_modules`, Node built-ins, and explicitly
excluded roots are not transformed.

## License

Apache 2.0
