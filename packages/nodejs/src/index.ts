/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

export {
  getNodeAutoInstrumentations,
  getResourceDetectors,
} from '@opentelemetry/auto-instrumentations-node';
export {
  HttpProfilingExporter,
  NodeProfiling,
} from '@beacon-observability/profiler-nodejs';
export { startProfilingFromEnv } from './profiling';
