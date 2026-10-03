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

Beacon Security is included in `1.2.0` and remains disabled by default. On
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
multipart `pprof` profiles together with auto-instrumented telemetry:

```bash
export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_PPROF_UPLOAD_URL="http://127.0.0.1:9529/profiles"
```

Supported profiling variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `OTEL_PROFILING_ENABLED` | Enables Beacon profiling | `false` |
| `OTEL_PROFILING_PPROF_UPLOAD_URL` | Required multipart profile endpoint | none |
| `OTEL_PROFILING_PPROF_HEADERS` | Comma-separated `name=value` or `name:value` headers | none |
| `OTEL_PROFILING_EXPORT_INTERVAL` | Collection interval in seconds | `60` |
| `OTEL_PROFILING_MEMORY_ENABLED` | Includes heap profiles | `false` |

The profiler emits a compatible multipart `pprof` layout. It is not an
implementation of the OpenTelemetry Profiles signal.

## Programmatic exports

The package exports `startProfilingFromEnv`, `NodeProfiling`, and
`HttpProfilingExporter`. Use the zero-code register entry point for the
supported out-of-the-box auto-instrumentation setup.

## Runtime support

Node.js `18.19+`, `20.6+`, `22`, and `24` are covered by the Beacon CI matrix.

## License

Apache 2.0
