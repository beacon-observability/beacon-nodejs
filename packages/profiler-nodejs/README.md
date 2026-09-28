# `@beacon-observability/profiler-nodejs`

This package provides a practical Node.js profiling bridge for OpenTelemetry
users. It is not an implementation of the OpenTelemetry Profiles signal.

The package:

- collects Node.js `wall` and `heap` profiles with `@datadog/pprof`
- reshapes Node.js profiles into the legacy `ddtrace` file layout expected by the target profiling receiver
- maps OpenTelemetry resource attributes to profiling tags
- exports `pprof` payloads to a profiling backend such as DataKit

## Status

This package is experimental.

## Installation

```sh
npm install ./packages/profiler-nodejs
```

See [USAGE.md](./USAGE.md) for a short module overview, configuration options,
defaults, and a minimal setup example.

## Usage

```ts
import { resourceFromAttributes } from '@opentelemetry/resources';
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
  SEMRESATTRS_DEPLOYMENT_ENVIRONMENT,
} from '@opentelemetry/semantic-conventions';
import {
  DatakitProfilingExporter,
  NodeProfiling,
} from '@beacon-observability/profiler-nodejs';

const profiler = new NodeProfiling({
  resource: resourceFromAttributes({
    [ATTR_SERVICE_NAME]: 'orders-api',
    [ATTR_SERVICE_VERSION]: '1.2.3',
    [SEMRESATTRS_DEPLOYMENT_ENVIRONMENT]: 'dev',
  }),
  exporter: new DatakitProfilingExporter({
    endpoint: 'http://127.0.0.1:9529/profiling/v1/input',
  }),
  profileTypes: ['wall', 'heap'],
  cpuProfilingEnabled: true,
});

await profiler.start();
```

## DataKit

DataKit profiling input accepts multipart profile uploads on
`/profiling/v1/input`.

```ts
new DatakitProfilingExporter({
  endpoint: 'http://127.0.0.1:9529/profiling/v1/input',
});
```

## Notes

- This package currently focuses on `wall` and `heap` profiles because those
  are the stable public capabilities exposed by `@datadog/pprof`.
- The exporter currently emits `wall.pprof` and `space.pprof` to match the
  legacy `ddtrace` Node.js profile layout consumed by the target receiver.
- `wall.pprof` contains `sample`, optional `cpu`, and `wall` sample types.
- `space.pprof` contains `objects` and `space` sample types.
- This layout is intentional: the compatible receiver looks for `wall.pprof`
  and `space.pprof`, not a single `auto.pprof`.
- The package is intended as a bridge for practical profiling integration in
  `opentelemetry-js-contrib`, not as a substitute for a future first-class
  OpenTelemetry Profiles SDK in `opentelemetry-js`.
