# Trace and Profile Demo

This example provides a quick local check that:

- trace data can be generated and exported; and
- profiles can be collected and sent through `HttpProfilingExporter`.

## Contents

- `app.js`: a minimal HTTP service whose `/work` route consumes some CPU,
  allocates memory for heap sampling, and calls a downstream HTTP service to
  produce a complete trace.
- `run-demo.js`: starts the sender, generates load, triggers profile collection,
  and sends telemetry to the configured endpoints.
- `mock-backend.js`: an optional local receiver for testing.

## Install

From this repository:

```bash
cd examples/trace-profile-demo
npm install
```

## Run the Complete Check

```bash
npm run demo
```

The default endpoints are:

- traces: `http://127.0.0.1:4318/v1/traces`
- metrics: `http://127.0.0.1:4318/v1/metrics`
- profiles: `http://127.0.0.1:8081/profiles`

The command prints the actual exporter endpoints, sends four `/work` requests,
and triggers one `/__collect-profile` request. If the configured receivers are
reachable, the trace, metric, and profile payloads are sent to them.

## Run Only the Application

```bash
npm run app
```

Override the endpoints when needed:

```bash
TRACE_ENDPOINT=http://127.0.0.1:4318/v1/traces \
METRIC_ENDPOINT=http://127.0.0.1:4318/v1/metrics \
PROFILE_ENDPOINT=http://127.0.0.1:8081/profiles \
npm run app
```

Then send requests:

```bash
curl 'http://127.0.0.1:8080/work?cpuMs=200&allocMb=12&pauseMs=100'
curl 'http://127.0.0.1:8080/__collect-profile'
```

## Notes

- Tracing uses the official Node SDK, HTTP instrumentation, and runtime-node
  instrumentation.
- Profiling uses the local
  `@beacon-observability/profiler-nodejs` development package.
- By default, this demo is a sender only and does not start a receiver.
- This demo checks whether signals can be emitted. It is not a production
  configuration or support claim.
