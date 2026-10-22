/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { NodeSDK } from '@opentelemetry/sdk-node';
import type { NodeSDKConfiguration } from '@opentelemetry/sdk-node';
import { diag, DiagConsoleLogger } from '@opentelemetry/api';
import { getStringFromEnv, diagLogLevelFromString } from '@opentelemetry/core';
// The inherited workspace may not have been compiled in a Beacon-only build.
// Resolve its public entry at runtime, as the published zero-code package does.
const {
  getNodeAutoInstrumentations,
  getResourceDetectors: getResourceDetectorsFromEnv,
} = require('@opentelemetry/auto-instrumentations-node') as {
  getNodeAutoInstrumentations(): NodeSDKConfiguration['instrumentations'];
  getResourceDetectors(): NodeSDKConfiguration['resourceDetectors'];
};

import { startProfilingFromEnv } from './profiling';
import { shutdownSecurity } from './lifecycle';

const logLevel = getStringFromEnv('OTEL_LOG_LEVEL');
if (logLevel !== undefined)
  diag.setLogger(new DiagConsoleLogger(), {
    logLevel: diagLogLevelFromString(logLevel),
  });
const instrumentations = getNodeAutoInstrumentations();
const resourceDetectors = getResourceDetectorsFromEnv();
if (logLevel !== undefined) diag.disable();
// Beacon owns this SDK so shutdown of its additional producers can be ordered
// before the shared Logs provider closes. The upstream register has independent
// signal/beforeExit handlers and cannot provide that ordering.
const sdk = new NodeSDK({ instrumentations, resourceDetectors });
try {
  sdk.start();
  diag.info('OpenTelemetry automatic instrumentation started successfully');
} catch (error) {
  diag.error('Unable to start Beacon Node.js tracing', error);
}

const profiler = startProfilingFromEnv();
let shutdownPromise: Promise<void> | undefined;

function shutdown(): Promise<void> {
  shutdownPromise ??= (async () => {
    try {
      await shutdownSecurity();
    } catch (error) {
      diag.error('Unable to stop Beacon Security', error);
    }
    try {
      await profiler?.shutdown();
    } catch (error) {
      diag.error('Unable to stop Beacon Node.js profiling', error);
    }
    await sdk
      .shutdown()
      .catch(error => diag.error('Unable to stop Beacon Node.js SDK', error));
  })();
  return shutdownPromise;
}

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, () => {
    // The once listener has already been removed. Application listeners own
    // their exit policy; only restore the default when Beacon was sole owner.
    const applicationOwnsSignal = process.listenerCount(signal) > 0;
    // Allow application-owned graceful draining to finish before shutting down
    // telemetry. Normal event-loop completion then uses the same ordered path.
    if (applicationOwnsSignal) return;
    let timer: NodeJS.Timeout;
    const deadline = new Promise<void>(resolve => {
      timer = setTimeout(resolve, 2500);
    });
    void Promise.race([shutdown(), deadline]).finally(() => {
      clearTimeout(timer);
      if (process.listenerCount(signal) === 0)
        process.kill(process.pid, signal);
    });
  });
}
process.once('beforeExit', () => {
  void shutdown();
});
