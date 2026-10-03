import { emitOtel } from './common/protocol.mjs';

// NodeSDK otherwise enables its environment-selected OTLP log/metric
// exporters. The trace fixture owns an in-memory trace exporter; disable only
// those implicit exporters so shutdown is bounded and cannot contact a host
// collector by accident.
process.env.OTEL_LOGS_EXPORTER ??= 'none';
process.env.OTEL_METRICS_EXPORTER ??= 'none';

const spans = [];
let sdk;
let exporter;
let started = false;
let securityShutdown;
let securityApiError;

try {
  const [
    { NodeSDK },
    { InMemorySpanExporter, SimpleSpanProcessor },
    { HttpInstrumentation },
    { ExpressInstrumentation },
    security,
  ] = await Promise.all([
    import('@opentelemetry/sdk-node'),
    import('@opentelemetry/sdk-trace-base'),
    import('@opentelemetry/instrumentation-http'),
    import('@opentelemetry/instrumentation-express'),
    import('@beacon-observability/security-nodejs'),
  ]);
  securityShutdown = security.shutdown;
  if (typeof securityShutdown !== 'function')
    throw new Error('security_shutdown_export_missing');
  exporter = new InMemorySpanExporter();
  sdk = new NodeSDK({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
    instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
  });
  await sdk.start();
  started = true;
} catch (error) {
  securityApiError = error.message;
  process.stderr.write(
    `BEACON_SECURITY_QA_OTEL_BOOTSTRAP_ERROR ${error.stack || error}\n`
  );
}

function compactSpan(span) {
  const context = span.spanContext?.() || {};
  return {
    name: span.name,
    traceId: context.traceId || null,
    spanId: context.spanId || null,
    parentSpanId: context.parentSpanId || null,
    kind: span.kind,
    attributes: span.attributes,
  };
}

globalThis.__securityQaShutdown = async ({ timeoutMillis = 2_000 } = {}) => {
  const deadline = Date.now() + timeoutMillis;
  if (typeof securityShutdown === 'function')
    await securityShutdown({ timeoutMillis });
  // InMemorySpanExporter clears its buffer from shutdown(); take the snapshot
  // before closing the SDK so the harness can inspect finished spans.
  const finished = exporter?.getFinishedSpans?.() || [];
  if (started) await sdk.shutdown();
  spans.push(...finished.map(compactSpan));
  emitOtel({
    started,
    securityApiAvailable: typeof securityShutdown === 'function',
    securityApiError,
    spans,
    timedOut: Date.now() > deadline,
  });
};
