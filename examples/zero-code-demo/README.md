# Zero-code Injection Demo

This application contains no OpenTelemetry or Beacon imports. It uses only the
Node.js HTTP module and is instrumented by preloading the Beacon package.

From an application where `@beacon-observability/nodejs` is installed:

```bash
export NODE_OPTIONS="--require @beacon-observability/nodejs/register"
export OTEL_SERVICE_NAME="zero-code-demo"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:9529"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"
node app.js
```

For OTLP/gRPC on port `4317`, use
`OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317` together with
`OTEL_EXPORTER_OTLP_PROTOCOL=grpc`.

The release smoke test starts a local receiver on `127.0.0.1:9529`, runs this
unchanged application with the preload configuration, and verifies both trace
and multipart profile payloads.
