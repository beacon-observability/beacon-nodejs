import { createRequire } from 'node:module';

const packageName =
  process.env.BEACON_SECURITY_QA_PACKAGE ||
  '@beacon-observability/security-nodejs';
const require = createRequire(import.meta.url);
process.env.OTEL_LOGS_EXPORTER ??= 'none';
process.env.OTEL_METRICS_EXPORTER ??= 'none';

let loaded;
let required;
try {
  loaded = await import(packageName);
  required = require(packageName);
} catch (error) {
  const result = {
    status: 'blocked',
    packageName,
    reason: 'package_not_available',
    error: error.message,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(2);
}

const candidate =
  loaded.SecurityInstrumentation ||
  loaded.default?.SecurityInstrumentation ||
  loaded.default;
const shutdown = loaded.shutdown || loaded.default?.shutdown;
const requiredCandidate =
  required.SecurityInstrumentation ||
  required.default?.SecurityInstrumentation ||
  required.default;
const requiredShutdown = required.shutdown || required.default?.shutdown;
const checks = [];
const check = (name, ok, detail) =>
  checks.push({ name, ok: Boolean(ok), detail });
check(
  'esm_exports',
  typeof candidate === 'function' && typeof shutdown === 'function',
  Object.keys(loaded).sort()
);
check(
  'cjs_exports',
  typeof requiredCandidate === 'function' &&
    typeof requiredShutdown === 'function',
  Object.keys(required).sort()
);

const registerA = await import(`${packageName}/register`);
const registerB = await import(`${packageName}/register`);
check('repeated_register_import', registerA && registerB, {
  firstLoaded: Boolean(registerA),
  secondLoaded: Boolean(registerB),
});

const first = new candidate();
const second = new requiredCandidate();
check('singleton_constructor', first === second, {
  firstType: first?.constructor?.name,
  same: first === second,
});

const [{ NodeSDK }, { InMemorySpanExporter, SimpleSpanProcessor }] =
  await Promise.all([
    import('@opentelemetry/sdk-node'),
    import('@opentelemetry/sdk-trace-base'),
  ]);
const exporter = new InMemorySpanExporter();
const sdk = new NodeSDK({
  spanProcessors: [new SimpleSpanProcessor(exporter)],
  instrumentations: [first],
});
await sdk.start();
check('sdk_accepts_instrumentation', first.isEnabled?.() === true, {
  enabled: first.isEnabled?.(),
  instrumentationName: first.instrumentationName,
});

await shutdown({ timeoutMillis: 1_000 });
const tracer = (await import('@opentelemetry/api')).trace.getTracer(
  'security-node-api-contract'
);
const hostSpan = tracer.startSpan('host-after-plugin-shutdown');
hostSpan.end();
await new Promise(resolve => setTimeout(resolve, 10));
const hostFinished = exporter.getFinishedSpans();
const hostSpanSurvived = hostFinished.some(
  span => span.name === 'host-after-plugin-shutdown'
);
await sdk.shutdown();
check('plugin_shutdown_preserves_host_sdk', hostSpanSurvived, {
  finishedBeforeHostShutdown: hostFinished.map(span => span.name),
});

const result = {
  status: checks.every(entry => entry.ok) ? 'pass' : 'fail',
  packageName,
  exports: Object.keys(loaded).sort(),
  cjsExports: Object.keys(required).sort(),
  checks,
  contract:
    'CJS/ESM exports, repeated register, singleton SecurityInstrumentation, SDK ownership boundary',
};
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (result.status !== 'pass') process.exit(1);
