import { logs } from '@opentelemetry/api-logs';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';
import {
  LoggerProvider,
  SimpleLogRecordProcessor,
} from '@opentelemetry/sdk-logs';

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
const logger = logs.getLogger('security-node-qa', '0.2.0');
logger.emit({
  severityText: 'INFO',
  body: 'security-node-qa-otlp-log',
  attributes: { 'qa.fixture': 'collector', 'qa.source': 'node-sdk' },
});
await provider.forceFlush();
await provider.shutdown();
process.stdout.write(JSON.stringify({ status: 'sent', endpoint }) + '\n');
