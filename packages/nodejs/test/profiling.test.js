/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('mocha');
const { startProfilingFromEnv } = require('../src/profiling');

describe('startProfilingFromEnv', () => {
  it('uses decoded OTel resource identity with service-name precedence', () => {
    const calls = [];
    const env = {
      OTEL_PROFILING_ENABLED: 'true',
      OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT: 'http://127.0.0.1',
      OTEL_RESOURCE_ATTRIBUTES:
        'service.name=checkout,service.version=v%201,deployment.environment.name=prod%2Ceast',
    };
    startProfilingFromEnv(env, fakeDependencies(calls));
    assert.equal(calls[1].options.serviceName, 'checkout');
    assert.equal(calls[1].options.serviceVersion, 'v 1');
    assert.equal(calls[1].options.deploymentEnvironment, 'prod,east');
    calls.length = 0;
    startProfilingFromEnv(
      { ...env, OTEL_SERVICE_NAME: 'override' },
      fakeDependencies(calls)
    );
    assert.equal(calls[1].options.serviceName, 'override');
  });

  it('falls back from overflowing environment intervals and isolates profiler initialization failure', () => {
    const calls = [];
    const env = {
      OTEL_PROFILING_ENABLED: 'true',
      OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT: 'http://127.0.0.1',
      OTEL_PROFILING_EXPORT_INTERVAL: '2147484',
    };
    startProfilingFromEnv(env, fakeDependencies(calls));
    assert.equal(calls[1].options.intervalMillis, 60000);
    assert.equal(
      startProfilingFromEnv(env, {
        createExporter() {
          throw new Error('missing native binding');
        },
      }),
      undefined
    );
  });
  it('does not start profiling unless explicitly enabled', () => {
    const calls = [];
    const profiler = startProfilingFromEnv({}, fakeDependencies(calls));

    assert.equal(profiler, undefined);
    assert.deepEqual(calls, []);
  });

  it('defaults to OTLP HTTP and allows file without parsing OTLP settings', () => {
    const calls = [];
    startProfilingFromEnv(
      { OTEL_PROFILING_ENABLED: 'true' },
      fakeDependencies(calls)
    );
    assert.equal(
      calls[0].options.endpoint,
      'http://localhost:4318/v1development/profiles'
    );
    calls.length = 0;
    startProfilingFromEnv(
      {
        OTEL_PROFILING_ENABLED: 'true',
        OTEL_PROFILING_EXPORTER: 'file',
        OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT: 'invalid',
        OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL: 'invalid',
      },
      fakeDependencies(calls)
    );
    assert.equal(calls[0].kind, 'file');
  });
  it('supports grpc and gives profile settings precedence', () => {
    const calls = [];
    startProfilingFromEnv(
      {
        OTEL_PROFILING_ENABLED: 'true',
        OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL: 'grpc',
      },
      fakeDependencies(calls)
    );
    assert.equal(calls[0].options.endpoint, 'http://localhost:4317');
    assert.equal(calls[0].options.protocol, 'grpc');
  });
  it('uses signal endpoints as-is and appends paths only to shared HTTP endpoints', () => {
    for (const [settings, expected] of [
      [
        { OTEL_EXPORTER_OTLP_ENDPOINT: 'http://collector:4318/base/' },
        'http://collector:4318/base/v1development/profiles',
      ],
      [
        {
          OTEL_EXPORTER_OTLP_ENDPOINT: 'http://shared:4318',
          OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT: 'http://signal:4318/custom',
        },
        'http://signal:4318/custom',
      ],
      [
        {
          OTEL_EXPORTER_OTLP_PROTOCOL: 'grpc',
          OTEL_EXPORTER_OTLP_ENDPOINT: 'http://collector:4317',
        },
        'http://collector:4317',
      ],
    ]) {
      const calls = [];
      startProfilingFromEnv(
        { OTEL_PROFILING_ENABLED: 'true', ...settings },
        fakeDependencies(calls)
      );
      assert.equal(calls[0].options.endpoint, expected);
    }
  });
  it('rejects removed exporter names', () => {
    for (const exporter of ['unknown', 'pprof_http', 'none']) {
      const calls = [];
      assert.equal(
        startProfilingFromEnv(
          { OTEL_PROFILING_ENABLED: 'true', OTEL_PROFILING_EXPORTER: exporter },
          fakeDependencies(calls)
        ),
        undefined
      );
      assert.equal(calls.length, 0);
    }
  });

  it('creates and starts profiling entirely from environment variables', async () => {
    const calls = [];
    const profiler = startProfilingFromEnv(
      {
        OTEL_PROFILING_ENABLED: 'true',
        OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT: 'http://127.0.0.1:9529/profiles',
        OTEL_EXPORTER_OTLP_PROFILES_HEADERS: 'X-API-Key:secret,tenant=demo',
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
          protocol: 'http/protobuf',
          timeoutMillis: 10000,
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
    createFileExporter(options) {
      calls.push({ kind: 'file', options });
      return { kind: 'fake-exporter' };
    },
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
