# Zero-code Injection Demo

This application contains no OpenTelemetry or Beacon imports. It uses only the
Node.js HTTP module and is instrumented by preloading the Beacon package.

From an application where `@beacon-observability/nodejs` is installed:

```bash
export NODE_OPTIONS="--require @beacon-observability/nodejs/register"
export OTEL_SERVICE_NAME="zero-code-demo"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:4317"
export OTEL_EXPORTER_OTLP_PROTOCOL="grpc"
node app.js
```

For OTLP/HTTP on port `9529`, use
`OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:9529` and select the HTTP
protocol accepted by that receiver.

The release smoke test starts a local receiver on an ephemeral port, runs this
unchanged application with the preload configuration, and verifies both trace
and multipart profile payloads. Set `BEACON_ZERO_CODE_RECEIVER_PORT` to use a
specific test port. Set
`BEACON_ZERO_CODE_EXTERNAL_ENDPOINT=http://127.0.0.1:4317` to exercise an
existing OTLP/gRPC receiver.
