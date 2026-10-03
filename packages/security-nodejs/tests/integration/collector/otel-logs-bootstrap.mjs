import { logs } from '@opentelemetry/api-logs';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';
import {
  LoggerProvider,
  SimpleLogRecordProcessor,
} from '@opentelemetry/sdk-logs';
import { NodeSDK } from '@opentelemetry/sdk-node';
import {
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from '@opentelemetry/sdk-trace-base';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';

const endpoint = process.env.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT;
if (!endpoint) throw new Error('OTEL_EXPORTER_OTLP_LOGS_ENDPOINT is required');

const provider = new LoggerProvider({
  processors: [
    new SimpleLogRecordProcessor({
      exporter: new OTLPLogExporter({ url: endpoint }),
    }),
  ],
});
logs.setGlobalLoggerProvider(provider);
globalThis.__securityQaLoggerProvider = provider;

const spanExporter = new InMemorySpanExporter();
const sdk = new NodeSDK({
  spanProcessors: [new SimpleSpanProcessor(spanExporter)],
  instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
});
await sdk.start();

globalThis.__securityQaFlushLogs = async () => {
  await provider.forceFlush();
  await provider.shutdown();
  await sdk.shutdown();
};
