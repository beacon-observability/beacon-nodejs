# Validation Demo

This example provides a quick local check that OpenTelemetry trace data can be
sent to an OTLP HTTP endpoint.

The default OTLP base endpoint is `http://localhost:4318`; the trace exporter
appends the signal path and sends to `http://localhost:4318/v1/traces`. The
example uses the standard OTLP HTTP default port.

## Install

```bash
cd examples/validation-demo
npm install
```

## Option 1: Send to a Receiver

For a local OTLP receiver, run:

```bash
npm run demo
```

The script:

- starts a local Express service;
- makes one request to itself to generate HTTP client and server spans;
- creates an additional manual `validation.business` span; and
- prints spans to the console for comparison with receiver output.

## Option 2: Inspect Requests with the Local Receiver

Start the receiver:

```bash
npm run receiver
```

Then run the demo in another terminal:

```bash
npm run demo
```

The receiver prints the request path, `content-type`, payload length, and a
hexadecimal preview of the first bytes.

## Optional Environment Variables

```bash
OTEL_SERVICE_NAME=my-validation-demo npm run demo
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 npm run demo
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318/v1/traces npm run demo
DEMO_PORT=8099 npm run demo
RECEIVER_PORT=4318 npm run receiver
```

## Custom Receiver Path

To configure a base endpoint rather than a complete signal URL, set
`OTEL_EXPORTER_OTLP_ENDPOINT`, for example `http://localhost:4318`.

To use another complete signal URL, set
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` directly:

```bash
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318/v1/traces npm run demo
```
