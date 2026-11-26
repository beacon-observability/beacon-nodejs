import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { logRecord } from '../src/log-record.mjs';
import { siemEvent } from '../src/siem.mjs';
import { dependencySnapshot } from '../src/sbom/snapshot.mjs';
import { Exporter } from '../src/exporter/index.mjs';

const fixtures = new URL('./fixtures/spec/current/', import.meta.url);
const read = path => readFile(new URL(path, fixtures), 'utf8');
const ajv = new Ajv2020({
  strict: true,
  strictTypes: false,
  strictRequired: false,
});
addFormats(ajv);
const validate = ajv.compile(
  JSON.parse(await read('schemas/beacon-security-siem-v1.schema.json'))
);
const { vectors } = JSON.parse(await read('test-vectors/siem-v1.json'));

for (const vector of vectors) {
  test(`shared SIEM vector: ${vector.name}`, async () => {
    const raw = await read(vector.input);
    const envelope = siemEvent(raw, vector.resource, vector.context);
    assert.deepEqual(envelope, JSON.parse(await read(vector.expected)));
    assert.equal(validate(envelope), true, ajv.errorsText(validate.errors));
    assert.equal(JSON.parse(JSON.stringify(envelope)).message, raw);
  });
}

test('raw escapes, whitespace and Unicode survive without changing outcome semantics', async () => {
  const input = JSON.parse(await read('examples/finding-v2.json'));
  input.stack = ['中文\\路径"\n😀'];
  input.attack_evidence.status = 'no_evidence';
  const raw = JSON.stringify(input, null, 2) + '\n';
  const result = siemEvent(
    raw,
    { 'tenant.id': 'configured' },
    { tenant_id: '', client_ip: '192.0.2.1:123' }
  );
  assert.equal(JSON.parse(JSON.stringify(result)).message, raw);
  assert.equal(result.outcome, 'unknown');
  assert.equal(result.tenant_id, 'configured');
  assert.equal(result.ip, '');
  assert.equal(result.actor, '');
  assert.equal(result.severity, 'informational');
  assert.throws(() => siemEvent('{'));
  assert.throws(() => siemEvent('{"schema_version":1}'), /unsupported/);
});

test('multipart planning budgets the escaped envelope and retains dependencies once', () => {
  const key = 'BEACON_SECURITY_EVIDENCE_MAX_BYTES';
  const original = process.env[key];
  process.env[key] = '1300';
  try {
    const identity = {
      instance_id: '11111111-1111-4111-8111-111111111111',
      service: { 'service.name': '服务"\\😀', 'tenant.id': 'tenant"' },
    };
    const records = Array.from({ length: 50 }, (_, i) => ({
      type: 'library',
      name: `${i}-包"\\😀`,
      version: '1',
      properties: [{ name: 'beacon:security:sbom:loaded', value: 'true' }],
    }));
    const input = {
      observed_at: '2026-11-23T00:00:00Z',
      started_at: '2026-11-22T00:00:00Z',
      uptime_ms: 86400000,
    };
    const parts = dependencySnapshot(input, records, identity);
    assert.ok(parts.length > 1);
    const ids = new Set();
    for (const [index, part] of parts.entries()) {
      const envelope = logRecord(part);
      assert.ok(Buffer.byteLength(envelope.body) <= 1300);
      assert.equal(part.part_index, index);
      assert.equal(part.part_count, parts.length);
      assert.equal(
        envelope.attributes.event_id,
        logRecord(part).attributes.event_id
      );
      ids.add(envelope.attributes.event_id);
      assert.equal(JSON.parse(envelope.body).schema_version, 2);
    }
    assert.equal(ids.size, parts.length);
    const names = parts.flatMap(part => part.dependencies.map(row => row.name));
    assert.equal(names.length, records.length);
    assert.equal(new Set(names).size, records.length);
  } finally {
    if (original === undefined) delete process.env[key];
    else process.env[key] = original;
  }
});

test('OTel context uses the invocation span and never falls back to the server', async () => {
  const keepAlive = setInterval(() => {}, 1000);
  const exporter = new Exporter();
  try {
    const { trace } = await import('@opentelemetry/api');
    const input = {
      trace_id: 'a'.repeat(32),
      span_id: 'c'.repeat(16),
      server_span_id: 'b'.repeat(16),
      trace_flags: 3,
    };
    assert.equal(
      trace.getSpanContext(await exporter._otelContext(input)).spanId,
      input.span_id
    );
    delete input.span_id;
    assert.equal(
      trace.getSpanContext(await exporter._otelContext(input)),
      undefined
    );
  } finally {
    await exporter.close();
    clearInterval(keepAlive);
  }
});
