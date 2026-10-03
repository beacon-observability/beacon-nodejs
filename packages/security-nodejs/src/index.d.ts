import type {
  Instrumentation,
  InstrumentationConfig,
} from '@opentelemetry/instrumentation';
import type { TracerProvider, MeterProvider } from '@opentelemetry/api';
import type { LoggerProvider } from '@opentelemetry/api-logs';
export declare class SecurityInstrumentation implements Instrumentation {
  constructor(config?: InstrumentationConfig);
  readonly instrumentationName: string;
  readonly instrumentationVersion: string;
  enable(): void;
  disable(): void;
  isEnabled(): boolean;
  getConfig(): InstrumentationConfig;
  setConfig(config: InstrumentationConfig): void;
  setTracerProvider(provider: TracerProvider): void;
  setMeterProvider(provider: MeterProvider): void;
  setLoggerProvider(provider: LoggerProvider): void;
}
/** Drains only resources owned by this plugin. It does not shut down the host SDK. */
export declare function shutdown(options?: {
  timeoutMillis?: number;
}): Promise<void>;
