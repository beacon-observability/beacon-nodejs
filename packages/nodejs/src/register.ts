/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import '@opentelemetry/auto-instrumentations-node/register';
import { diag } from '@opentelemetry/api';

import { startProfilingFromEnv } from './profiling';

const profiler = startProfilingFromEnv();
let shutdownPromise: Promise<void> | undefined;

function shutdownProfiling(): Promise<void> {
  if (profiler === undefined) {
    return Promise.resolve();
  }
  shutdownPromise ??= profiler.shutdown().catch(error => {
    diag.error('Unable to stop Beacon Node.js profiling', error);
  });
  return shutdownPromise;
}

if (profiler !== undefined) {
  process.once('SIGTERM', () => {
    void shutdownProfiling();
  });
  process.once('SIGINT', () => {
    void shutdownProfiling();
  });
  process.once('beforeExit', shutdownProfiling);
}
