/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Resource } from '@opentelemetry/resources';

export type NodeProfileType = 'wall' | 'heap';

export interface CollectedProfile {
  type: string;
  filename: string;
  data: Buffer;
}

export interface ProfileBatch {
  startTime: Date;
  endTime: Date;
  family: 'nodejs';
  format: 'pprof';
  tags: Record<string, string>;
  profiles: CollectedProfile[];
}

export interface ProfileExporter {
  export(batch: ProfileBatch): Promise<void>;
  shutdown?(): Promise<void>;
}

export interface OtlpProfilingExporterOptions {
  endpoint: string;
  protocol?: 'http/protobuf' | 'grpc';
  timeoutMillis?: number;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
}

export interface FileProfilingExporterOptions {
  directory: string;
}

export interface NodeProfilingOptions {
  exporter: ProfileExporter;
  resource?: Resource;
  tags?: Record<string, string | number | boolean>;
  serviceName?: string;
  serviceVersion?: string;
  deploymentEnvironment?: string;
  hostName?: string;
  profileTypes?: NodeProfileType[];
  intervalMillis?: number;
  wallDurationMillis?: number;
  heapSamplingIntervalBytes?: number;
  /**
   * Enables CPU time collection inside the wall profile.
   *
   * This follows the Node.js profiling model used by Datadog's profiler where
   * `cpu-time` is emitted as a sample type in the wall profile.
   */
  cpuProfilingEnabled?: boolean;
  /**
   * @deprecated Use `cpuProfilingEnabled` instead.
   */
  collectCpuTime?: boolean;
}
