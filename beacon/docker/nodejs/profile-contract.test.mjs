import assert from 'node:assert/strict';
import { test } from 'node:test';
import { profileContract } from './profile-contract.mjs';

const endpoint = 'http://127.0.0.1:4318';

test('published multipart packages keep their original acceptance protocol', () => {
  const contract = profileContract({ HttpProfilingExporter: class {} });
  assert.deepEqual(contract.environment(endpoint), {
    OTEL_PROFILING_PPROF_UPLOAD_URL: `${endpoint}/profiles`,
  });
  assert.equal(contract.path, '/profiles');
  assert(
    contract.matches({
      contentType: 'multipart/form-data; boundary=test',
      body: Buffer.from('wall.pprof event.json'),
    })
  );
  assert(
    !contract.matches({
      contentType: 'application/x-protobuf',
      body: Buffer.alloc(0),
    })
  );
});

test('OTLP candidates use the new signal endpoint and reject multipart', () => {
  const contract = profileContract({ OtlpProfilingExporter: class {} });
  assert.deepEqual(contract.environment(endpoint), {
    OTEL_PROFILING_EXPORTER: 'otlp',
    OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT: `${endpoint}/v1development/profiles`,
    OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL: 'http/protobuf',
  });
  assert.equal(contract.path, '/v1development/profiles');
  assert(contract.matches({ contentType: 'application/x-protobuf' }));
  assert(
    !contract.matches({ contentType: 'multipart/form-data; boundary=test' })
  );
});

test('unknown candidates fail instead of silently skipping profiling', () => {
  assert.throws(() => profileContract({}), /recognized profiling exporter/);
});
