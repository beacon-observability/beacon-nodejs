# Profiling usage

See the [package guide](README.md) for OTLP/file configuration and exporter APIs.

## Profiler Options

### `NodeProfiling`

```ts
new NodeProfiling({
  exporter,
  resource,
  tags,
  serviceName,
  serviceVersion,
  deploymentEnvironment,
  hostName,
  profileTypes,
  intervalMillis,
  wallDurationMillis,
  heapSamplingIntervalBytes,
  cpuProfilingEnabled,
});
```

Parameters:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `exporter` | `ProfileExporter` | required | Exporter used to send collected profiles. |
| `resource` | `Resource` | unset | OpenTelemetry resource used to derive tags such as service name and version. |
| `tags` | `Record<string, string \| number \| boolean>` | unset | Extra profiling tags included as profile resource metadata. |
| `serviceName` | `string` | derived from `resource` | Overrides the service name tag. |
| `serviceVersion` | `string` | derived from `resource` | Overrides the service version tag. |
| `deploymentEnvironment` | `string` | derived from `resource` | Overrides the environment tag. |
| `hostName` | `string` | derived from OS hostname | Overrides the host tag. |
| `profileTypes` | `('wall' \| 'heap')[]` | `['wall', 'heap']` | Profile types collected on each cycle. |
| `intervalMillis` | `number` | `60000` | Interval between collection cycles. |
| `wallDurationMillis` | `number` | `10000` | Duration of one wall profile capture. |
| `heapSamplingIntervalBytes` | `number` | `524288` | Heap sampling interval passed to `@datadog/pprof`. |
| `cpuProfilingEnabled` | `boolean` | `true` | Enables CPU time data inside `wall.pprof`. |
| `collectCpuTime` | `boolean` | deprecated | Deprecated alias of `cpuProfilingEnabled`. |

## Lifecycle

- `await profiler.start()`: starts the periodic collection loop.
- `await profiler.collectOnce()`: collects and exports one batch.
- `await profiler.shutdown()`: stops collection and shuts down the exporter.

Standalone collection defaults to wall and heap profiles; zero-code collection defaults
to wall profiles and enables heap with `OTEL_PROFILING_MEMORY_ENABLED=true`.
