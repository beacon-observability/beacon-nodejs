# `@beacon-observability/nodejs`

Beacon Node.js provides zero-code OpenTelemetry auto-instrumentation and the
optional Beacon profiler in one package.

## Install

After version `1.1.0` is published, install it with
`npm install @beacon-observability/nodejs@1.1.0`. Before publication, use the
packed source candidate produced by the repository smoke test.

## Zero-code injection

Start an unchanged Node.js application by preloading the Beacon register entry
point:

```bash
export NODE_OPTIONS="--require @beacon-observability/nodejs/register"
export OTEL_SERVICE_NAME="my-node-service"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:9529"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"
node app.js
```

For an OTLP/gRPC receiver on the standard port instead, set the endpoint to
`http://127.0.0.1:4317` and the protocol to `grpc`.

The package uses the standard OpenTelemetry Node.js environment variables for
traces, metrics, logs, propagators, resource attributes, and instrumentation
selection. For example, use `OTEL_NODE_ENABLED_INSTRUMENTATIONS=http,express`
to limit the enabled instrumentation set.

The application must not initialize another OpenTelemetry SDK when the register
entry point is preloaded.

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

The package re-exports `getNodeAutoInstrumentations`,
`getResourceDetectors`, `NodeProfiling`, and `HttpProfilingExporter`. Use the
zero-code register entry point for the supported out-of-the-box setup.

## Runtime support

Node.js `18.19+`, `20.6+`, `22`, and `24` are covered by the Beacon CI matrix.

## License

Apache 2.0
