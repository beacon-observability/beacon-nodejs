import { NodeSDK } from '@opentelemetry/sdk-node';
import { SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { shutdown as securityShutdown } from '@beacon-observability/security-nodejs';
import { getRuntime } from '../../../src/core/runtime.mjs';
import { trackingBytes } from '../../../src/core/state.mjs';

process.env.OTEL_LOGS_EXPORTER ??= 'none';
process.env.OTEL_METRICS_EXPORTER ??= 'none';

class CountingSpanExporter {
  exportedSpans = 0;
  exportCalls = 0;
  exportErrors = 0;

  export(spans, callback) {
    this.exportCalls += 1;
    this.exportedSpans += spans.length;
    callback({ code: 0 });
  }

  forceFlush() {
    return Promise.resolve();
  }
  shutdown() {
    return Promise.resolve();
  }
}

const exporter = new CountingSpanExporter();
const sdk = new NodeSDK({
  spanProcessors: [new SimpleSpanProcessor(exporter)],
  instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
});
await sdk.start();

function snapshot() {
  const runtime = getRuntime();
  const pluginExporter = runtime?.exporter;
  const ledger = pluginExporter?.ledger;
  const delivery = pluginExporter?.delivery?.() || {};
  const memory = process.memoryUsage();
  return {
    at: new Date().toISOString(),
    trackingBytes: trackingBytes(),
    active_requests: ledger?.activeRequests ?? null,
    requests_started: ledger?.counts?.requests_started ?? 0,
    requests_completed: ledger?.counts?.requests_completed ?? 0,
    requests_incomplete: ledger?.counts?.requests_incomplete ?? 0,
    security_queue_depth: delivery.security_queue_depth ?? null,
    sbom_queue_depth: delivery.sbom_queue_depth ?? null,
    security_draining: Boolean(pluginExporter?.draining?.security),
    sbom_draining: Boolean(pluginExporter?.draining?.sbom),
    dropped: delivery.dropped ?? null,
    security_dropped: delivery.security_dropped ?? null,
    sbom_dropped: delivery.sbom_dropped ?? null,
    rssBytes: memory.rss,
    heapUsedBytes: memory.heapUsed,
    otelExportedSpans: exporter.exportedSpans,
    otelExportCalls: exporter.exportCalls,
  };
}

let latestIdle = snapshot();
let maxActiveRequests = latestIdle.active_requests || 0;
let maxTrackingBytes = latestIdle.trackingBytes || 0;
const sampler = setInterval(() => {
  const value = snapshot();
  maxActiveRequests = Math.max(maxActiveRequests, value.active_requests || 0);
  maxTrackingBytes = Math.max(maxTrackingBytes, value.trackingBytes || 0);
  if (value.active_requests === 0 && value.trackingBytes === 0)
    latestIdle = value;
}, 100);
sampler.unref?.();

globalThis.__securityQaSoakSnapshot = () => ({
  ...latestIdle,
  sampleKind: 'last_idle',
  maxActiveRequests,
  maxTrackingBytes,
  current: snapshot(),
});
globalThis.__securityQaSoakShutdown = async ({
  timeoutMillis = 5_000,
} = {}) => {
  clearInterval(sampler);
  const before = globalThis.__securityQaSoakSnapshot();
  const started = Date.now();
  await securityShutdown({ timeoutMillis });
  await sdk.shutdown();
  return {
    before,
    exporter: { ...exporter },
    shutdownMillis: Date.now() - started,
    timeoutMillis,
  };
};
