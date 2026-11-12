# Beacon Node.js Profiling

This experimental package collects Node.js wall and heap profiles using
`@datadog/pprof`. Source changes below require a new Beacon release.

## Zero-code setup

Keep the preload from [Beacon Node.js](../nodejs/README.md), then configure one exporter:

```bash
export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT=http://localhost:4318/v1development/profiles
```

For gRPC, set `OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL=grpc` and
`OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT=http://localhost:4317`.
Use `https://` endpoints for TLS. The receiver must support the development
OTLP Profiles schema from OpenTelemetry Proto v1.11.0, not only OTLP traces.

For local gzip pprof files:

```bash
export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_EXPORTER=file
export OTEL_PROFILING_FILE_PATH=./profiles
```

File export does not read or validate OTLP endpoint, protocol, headers or timeout.

## Export configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `OTEL_PROFILING_EXPORTER` | `otlp` | `otlp` or `file`; disable profiling with `OTEL_PROFILING_ENABLED=false`. |
| `OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL` | Shared OTLP protocol, then `http/protobuf` | `http/protobuf` or `grpc`. |
| `OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT` | Protocol-dependent | Exact signal endpoint. HTTP defaults to `http://localhost:4318/v1development/profiles`; gRPC defaults to `http://localhost:4317`. |
| `OTEL_EXPORTER_OTLP_PROFILES_HEADERS` | Shared OTLP headers | Comma-separated, percent-encoded `key=value` pairs. |
| `OTEL_EXPORTER_OTLP_PROFILES_TIMEOUT` | Shared OTLP timeout, then `10000` | Milliseconds. |
| `OTEL_PROFILING_FILE_PATH` | `otel-profiles` | Local output directory, used only by `file`. |

When the signal endpoint is unset, the shared `OTEL_EXPORTER_OTLP_ENDPOINT`
is used. HTTP appends `/v1development/profiles`; gRPC uses the shared endpoint as-is.
The previous HTTP multipart exporter and its configuration are removed.

`OTEL_PROFILING_EXPORT_INTERVAL` is in seconds (default `60`). Wall collection
is on by default; `OTEL_PROFILING_MEMORY_ENABLED=true` adds heap samples.

## Standalone API

```javascript
const { NodeProfiling, OtlpProfilingExporter, FileProfilingExporter } =
  require('@beacon-observability/profiler-nodejs');
const profiler = new NodeProfiling({
  exporter: new OtlpProfilingExporter({
    endpoint: 'http://localhost:4317',
    protocol: 'grpc',
  }),
});
await profiler.start();
// Before application shutdown:
await profiler.shutdown();
```

Use `new FileProfilingExporter({directory: './profiles'})` for local output.
The converter preserves functions, locations, stacks and sample values; each
pprof sample type becomes a separate OTLP Profile. HTTP and gRPC share the same
protobuf request. Profiling remains opt-in and native loading failures are isolated.
