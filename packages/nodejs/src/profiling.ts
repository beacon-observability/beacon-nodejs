/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { diag } from '@opentelemetry/api';
import type {
  ProfileExporter,
  NodeProfiling,
} from '@beacon-observability/profiler-nodejs';
import type {
  OtlpProfilingExporterOptions,
  NodeProfilingOptions,
  FileProfilingExporterOptions,
} from '@beacon-observability/profiler-nodejs';

const DEFAULT_EXPORT_INTERVAL_SECONDS = 60;

interface ProfilingEnvironment {
  [key: string]: string | undefined;
}

interface ProfilingDependencies {
  createExporter(options: OtlpProfilingExporterOptions): ProfileExporter;
  createFileExporter(options: FileProfilingExporterOptions): ProfileExporter;
  createProfiler(options: NodeProfilingOptions): NodeProfiling;
}

const defaultDependencies: ProfilingDependencies = {
  createFileExporter: options => {
    const { FileProfilingExporter } =
      require('@beacon-observability/profiler-nodejs') as typeof import('@beacon-observability/profiler-nodejs');
    return new FileProfilingExporter(options);
  },
  createExporter: options => {
    const { OtlpProfilingExporter } =
      require('@beacon-observability/profiler-nodejs') as typeof import('@beacon-observability/profiler-nodejs');
    return new OtlpProfilingExporter(options);
  },
  createProfiler: options => {
    const { NodeProfiling } =
      require('@beacon-observability/profiler-nodejs') as typeof import('@beacon-observability/profiler-nodejs');
    return new NodeProfiling(options);
  },
};

export function startProfilingFromEnv(
  env: ProfilingEnvironment = process.env,
  dependencies: ProfilingDependencies = defaultDependencies
): NodeProfiling | undefined {
  if (!parseBoolean(env.OTEL_PROFILING_ENABLED, false)) {
    return undefined;
  }

  const exporterName = nonEmpty(env.OTEL_PROFILING_EXPORTER) ?? 'otlp';
  if (!['otlp', 'file'].includes(exporterName)) {
    diag.error(
      `Unsupported profiling exporter '${exporterName}'; profiling is disabled`
    );
    return undefined;
  }
  const intervalSeconds = positiveNumber(
    env.OTEL_PROFILING_EXPORT_INTERVAL,
    DEFAULT_EXPORT_INTERVAL_SECONDS,
    'OTEL_PROFILING_EXPORT_INTERVAL'
  );
  const intervalMillis = intervalSeconds * 1000;
  const resourceAttributes = parseKeyValueList(env.OTEL_RESOURCE_ATTRIBUTES);
  const memoryEnabled = parseBoolean(env.OTEL_PROFILING_MEMORY_ENABLED, false);

  try {
    let exporter: ProfileExporter;
    if (exporterName === 'file') {
      exporter = dependencies.createFileExporter({
        directory: nonEmpty(env.OTEL_PROFILING_FILE_PATH) ?? 'otel-profiles',
      });
    } else {
      const protocol =
        nonEmpty(env.OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL) ??
        nonEmpty(env.OTEL_EXPORTER_OTLP_PROTOCOL) ??
        'http/protobuf';
      if (protocol !== 'http/protobuf' && protocol !== 'grpc')
        throw new Error(`Unsupported OTLP Profiles protocol '${protocol}'`);
      const sharedEndpoint = nonEmpty(env.OTEL_EXPORTER_OTLP_ENDPOINT);
      const endpoint =
        nonEmpty(env.OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT) ??
        (protocol === 'grpc'
          ? (sharedEndpoint ?? 'http://localhost:4317')
          : `${(sharedEndpoint ?? 'http://localhost:4318').replace(/\/+$/, '')}/v1development/profiles`);
      exporter = dependencies.createExporter({
        endpoint,
        protocol,
        headers: parseHeaders(
          env.OTEL_EXPORTER_OTLP_PROFILES_HEADERS ??
            env.OTEL_EXPORTER_OTLP_HEADERS
        ),
        timeoutMillis: positiveNumber(
          env.OTEL_EXPORTER_OTLP_PROFILES_TIMEOUT ??
            env.OTEL_EXPORTER_OTLP_TIMEOUT,
          10000,
          'OTEL_EXPORTER_OTLP_PROFILES_TIMEOUT'
        ),
      });
    }
    const profiler = dependencies.createProfiler({
      exporter,
      intervalMillis,
      wallDurationMillis: Math.min(10_000, intervalMillis),
      profileTypes: memoryEnabled ? ['wall', 'heap'] : ['wall'],
      serviceName:
        nonEmpty(env.OTEL_SERVICE_NAME) ??
        nonEmpty(resourceAttributes['service.name']),
      serviceVersion: resourceAttributes['service.version'],
      deploymentEnvironment:
        resourceAttributes['deployment.environment.name'] ??
        resourceAttributes['deployment.environment'],
      hostName: resourceAttributes['host.name'],
    });

    void profiler.start().then(
      () => diag.info('Beacon Node.js profiling started successfully'),
      error => diag.error('Unable to start Beacon Node.js profiling', error)
    );
    return profiler;
  } catch (error) {
    diag.error('Unable to initialize optional Beacon Node.js profiling', error);
    return undefined;
  }
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === '') {
    return fallback;
  }
  return ['true', '1', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function positiveNumber(
  value: string | undefined,
  fallback: number,
  variableName: string
): number {
  if (value === undefined || value.trim() === '') {
    return fallback;
  }
  const parsed = Number(value);
  if (Number.isFinite(parsed) && parsed >= 0.001 && parsed <= 2147483.647) {
    return parsed;
  }
  diag.warn(`${variableName} must be a positive number; using ${fallback}`);
  return fallback;
}

function parseHeaders(value: string | undefined): Record<string, string> {
  return parseKeyValueList(value, true);
}

function parseKeyValueList(
  value: string | undefined,
  allowColon = false
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const item of value?.split(',') ?? []) {
    const trimmed = item.trim();
    if (trimmed === '') {
      continue;
    }
    const equalsIndex = trimmed.indexOf('=');
    const colonIndex = allowColon ? trimmed.indexOf(':') : -1;
    const separatorIndex =
      equalsIndex >= 0 && colonIndex >= 0
        ? Math.min(equalsIndex, colonIndex)
        : Math.max(equalsIndex, colonIndex);
    if (separatorIndex <= 0) {
      continue;
    }
    const key = trimmed.slice(0, separatorIndex).trim();
    const itemValue = trimmed.slice(separatorIndex + 1).trim();
    if (key !== '') {
      {
        try {
          result[decodeURIComponent(key)] = decodeURIComponent(itemValue);
        } catch {
          diag.warn('Invalid encoding in OTEL_RESOURCE_ATTRIBUTES');
        }
      }
    }
  }
  return result;
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed === undefined || trimmed === '' ? undefined : trimmed;
}
