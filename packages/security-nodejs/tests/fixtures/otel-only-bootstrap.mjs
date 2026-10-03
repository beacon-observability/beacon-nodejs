import { emitOtel } from './common/protocol.mjs';

process.env.OTEL_LOGS_EXPORTER ??= 'none';
process.env.OTEL_METRICS_EXPORTER ??= 'none';

let sdk;
let exporter;
let started = false;
try {
  const [
    { NodeSDK },
    { InMemorySpanExporter, SimpleSpanProcessor },
    { HttpInstrumentation },
    { ExpressInstrumentation },
  ] = await Promise.all([
    import('@opentelemetry/sdk-node'),
    import('@opentelemetry/sdk-trace-base'),
    import('@opentelemetry/instrumentation-http'),
    import('@opentelemetry/instrumentation-express'),
  ]);
  exporter = new InMemorySpanExporter();
  sdk = new NodeSDK({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
    instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
  });
  await sdk.start();
  started = true;
} catch (error) {
  process.stderr.write(
    `BEACON_SECURITY_QA_OTEL_BOOTSTRAP_ERROR ${error.stack || error}\n`
  );
}

globalThis.__securityQaShutdown = async ({ timeoutMillis = 2_000 } = {}) => {
  const startedAt = Date.now();
  const spans = (exporter?.getFinishedSpans?.() || []).map(span => {
    const context = span.spanContext?.() || {};
    return {
      name: span.name,
      traceId: context.traceId || null,
      spanId: context.spanId || null,
      kind: span.kind,
    };
  });
  if (started) await sdk.shutdown();
  emitOtel({
    started,
    securityApiAvailable: false,
    spans,
    timedOut: Date.now() - startedAt > timeoutMillis,
  });
};
