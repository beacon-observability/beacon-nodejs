# `@beacon-observability/nodejs`

Beacon Node.js provides zero-code OpenTelemetry auto-instrumentation and the
optional Beacon profiler and Security runtime in one package.

## Install

Install the current release with:

```bash
npm install @beacon-observability/nodejs
```

## Zero-code injection

Start an unchanged Node.js application by preloading the Beacon register entry
point:

```bash
export NODE_OPTIONS="--require @beacon-observability/nodejs/register"
export OTEL_SERVICE_NAME="my-node-service"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:4317"
export OTEL_EXPORTER_OTLP_PROTOCOL="grpc"
node app.js
```

For an OTLP/HTTP receiver on port `9529`, set the endpoint to
`http://127.0.0.1:9529` and select the protocol supported by that receiver,
such as `http/protobuf` or `http/json`.

The package uses the standard OpenTelemetry Node.js environment variables for
traces, metrics, logs, propagators, resource attributes, and instrumentation
selection. For example, use `OTEL_NODE_ENABLED_INSTRUMENTATIONS=http,express`
to limit the enabled instrumentation set.

The application must not initialize another OpenTelemetry SDK when the register
entry point is preloaded.

## Optional Security

Beacon Security was introduced in `1.2.0` and remains disabled by default. On
Node.js 22.22.3+ or 24.11.1+, use
the ESM preload entry point and explicitly select the application source root:

```bash
export NODE_OPTIONS="--import @beacon-observability/nodejs/register"
export BEACON_SECURITY_ENABLED=true
export BEACON_SECURITY_NODE_INCLUDE=/srv/app
```

It reuses the normal `OTEL_*` resource and Logs exporter configuration.
Runtime SBOM is enabled with the Security lifecycle unless
`BEACON_SECURITY_SBOM_ENABLED=false`. Diagnostic files remain disabled unless
`BEACON_SECURITY_LOCAL_OUTPUT_ENABLED=true`; their default directory is
`./beacon-security-output/<instance-id>`.

The CommonJS `--require @beacon-observability/nodejs/register` entry point
continues to initialize tracing and profiling but cannot install the synchronous
ESM source transformer. Use `--import` whenever Security is enabled.

The Security workspace provides a
[Kubernetes Deployment example](../security-nodejs/examples/kubernetes/deployment.yaml)
that bakes this complete package into the application image. It does not need a
separate Security image, sidecar, or init container.

## Optional profiling

Profiling is disabled unless explicitly enabled. To export compatible
OTLP Profiles or local pprof files alongside auto-instrumented telemetry:

```bash
export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT=http://localhost:4318/v1development/profiles
```

For gRPC set `OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL=grpc` and use
`http://localhost:4317`. For local files set `OTEL_PROFILING_EXPORTER=file` and
`OTEL_PROFILING_FILE_PATH=./profiles`; file export does not parse endpoint settings.
See the [profiling guide](../profiler-nodejs/README.md) for the full reference
and standalone `OtlpProfilingExporter` / `FileProfilingExporter` APIs.
These exporter changes require a new Beacon release.
