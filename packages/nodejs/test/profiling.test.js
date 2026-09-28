/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('mocha');
const { startProfilingFromEnv } = require('../src/profiling');

describe('startProfilingFromEnv', () => {
  it('does not start profiling unless explicitly enabled', () => {
    const calls = [];
    const profiler = startProfilingFromEnv({}, fakeDependencies(calls));

    assert.equal(profiler, undefined);
    assert.deepEqual(calls, []);
  });

  it('requires an upload URL when profiling is enabled', () => {
    const calls = [];
    const profiler = startProfilingFromEnv(
      { OTEL_PROFILING_ENABLED: 'true' },
      fakeDependencies(calls)
    );

    assert.equal(profiler, undefined);
    assert.deepEqual(calls, []);
  });

  it('creates and starts profiling entirely from environment variables', async () => {
    const calls = [];
    const profiler = startProfilingFromEnv(
      {
        OTEL_PROFILING_ENABLED: 'true',
        OTEL_PROFILING_PPROF_UPLOAD_URL: 'http://127.0.0.1:9529/profiles',
        OTEL_PROFILING_PPROF_HEADERS: 'X-API-Key:secret,tenant=demo',
        OTEL_PROFILING_EXPORT_INTERVAL: '2.5',
        OTEL_PROFILING_MEMORY_ENABLED: 'false',
        OTEL_SERVICE_NAME: 'checkout',
        OTEL_RESOURCE_ATTRIBUTES:
          'service.version=1.2.3,deployment.environment.name=prod,host.name=node-a',
      },
      fakeDependencies(calls)
    );

    assert.notEqual(profiler, undefined);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(calls, [
      {
        kind: 'exporter',
        options: {
          endpoint: 'http://127.0.0.1:9529/profiles',
          headers: { 'X-API-Key': 'secret', tenant: 'demo' },
        },
      },
      {
        kind: 'profiler',
        options: {
          exporter: { kind: 'fake-exporter' },
          intervalMillis: 2500,
          wallDurationMillis: 2500,
          profileTypes: ['wall'],
          serviceName: 'checkout',
          serviceVersion: '1.2.3',
          deploymentEnvironment: 'prod',
          hostName: 'node-a',
        },
      },
      { kind: 'start' },
    ]);
  });
});

function fakeDependencies(calls) {
  return {
    createExporter(options) {
      calls.push({ kind: 'exporter', options });
      return { kind: 'fake-exporter' };
    },
    createProfiler(options) {
      calls.push({ kind: 'profiler', options });
      return {
        async start() {
          calls.push({ kind: 'start' });
        },
        async shutdown() {},
      };
    },
  };
}
