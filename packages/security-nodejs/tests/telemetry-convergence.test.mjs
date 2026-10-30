import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { Worker } from 'node:worker_threads';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { onlineEvent } from '../src/schema.mjs';
import { dependencySnapshot } from '../src/sbom/snapshot.mjs';
import { Exporter } from '../src/exporter/index.mjs';

const identity = {
  instance_id: '11111111-1111-4111-8111-111111111111',
  service: { 'service.name': 'demo' },
};
const schema = JSON.parse(
  await readFile(
    new URL(
      './fixtures/spec/beacon-security-event-v2.schema.json',
      import.meta.url
    ),
    'utf8'
  )
);
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
});
addFormats(ajv);
const validateEvent = ajv.compile(schema);

function assertSchema(event) {
  assert.equal(
    validateEvent(event),
    true,
    ajv.errorsText(validateEvent.errors)
  );
}

async function waitFor(predicate, timeout = 4000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await sleep(20);
  }
  assert.fail('timed out waiting for Security telemetry');
}

test('finding projection keeps request evidence while dropping v1 duplicate fields', () => {
  const finding = onlineEvent({
    event_name: 'beacon.security.finding',
    instance_id: identity.instance_id,
    observed_at: '2026-10-27T09:20:00.000Z',
    finding_id: `finding-${'a'.repeat(64)}`,
    fingerprint_version: 1,
    occurrence_id: 'ev-1',
    evidence_id: 'ev-1',
    occurrences_total: 10,
    rule: 'sql_injection',
    attack_evidence: {
      status: 'unknown',
      reason: 'sql_dialect_unsupported',
      outcome: 'not_assessed',
    },
    request: { method: 'GET', route: '/sql', status_code: 200, framework: '' },
    sink: {
      function: 'query',
      role: 'sql_template',
      location: 'db.js:1',
      operation: '',
    },
    component: { name: 'pg', version: '8.0.0', hash: 'abc', revision: 4 },
    trace_id: '1'.repeat(32),
    server_span_id: '2'.repeat(16),
    current_span_id: '2'.repeat(16),
    sources: [{ type: 'http.request.parameter', name: 'q' }],
    propagation: [],
    evidence_sampled: false,
    evidence_sample_reason: 'interval',
    truncated: false,
    coverage_gaps: [],
    service: { 'service.name': 'demo' },
  });
  assert.equal(finding.schema_version, 2);
  assert.equal(finding.occurrence_id, 'ev-1');
  assert.deepEqual(finding.attack_evidence, {
    status: 'unknown',
    reason: 'sql_dialect_unsupported',
  });
  assert.deepEqual(finding.component, {
    name: 'pg',
    version: '8.0.0',
    hash: 'abc',
  });
  assert.equal(finding.collection_complete, true);
  assertSchema(finding);
  for (const field of [
    'evidence_id',
    'occurrences_total',
    'service',
    'current_span_id',
    'propagation',
    'truncated',
  ])
    assert.equal(Object.hasOwn(finding, field), false, field);
});

test('inventory fragments only when needed and retains every loaded dependency', () => {
  const records = [
    {
      type: 'library',
      name: 'a',
      version: '1',
      properties: [{ name: 'beacon:security:sbom:loaded', value: 'true' }],
    },
    {
      type: 'library',
      name: 'b',
      version: '2',
      properties: [{ name: 'beacon:security:sbom:loaded', value: 'true' }],
    },
    {
      type: 'library',
      name: 'not-loaded',
      properties: [{ name: 'beacon:security:sbom:loaded', value: 'false' }],
    },
  ];
  const events = dependencySnapshot(
    {
      instance_id: identity.instance_id,
      observed_at: '2026-10-27T09:20:00.000Z',
      started_at: '2026-10-27T09:00:00.000Z',
      uptime_ms: 1200000,
    },
    records,
    identity
  );
  assert.equal(events.length, 1);
  assert.deepEqual(events[0].dependencies, [
    { name: 'a', version: '1' },
    { name: 'b', version: '2' },
  ]);
  assert.equal(events[0].schema_version, 2);
  assertSchema(events[0]);
  for (const field of [
    'part_index',
    'part_count',
    'sbom_id',
    'revision',
    'status',
  ])
    assert.equal(Object.hasOwn(events[0], field), false, field);
});

test('unchanged SBOM collection emits a fresh inventory on each configured cycle', async () => {
  const messages = [];
  const worker = new Worker(
    new URL('../src/sbom/worker.mjs', import.meta.url),
    {
      workerData: { identity, include: [], settings: { refreshSeconds: 1 } },
    }
  );
  worker.on('message', message => messages.push(message));
  try {
    worker.postMessage({ type: 'refresh' });
    await waitFor(
      () =>
        messages.filter(message => message.type === 'published').length >= 2,
      10000
    );
    const rounds = messages.filter(message => message.type === 'published');
    const first = rounds[0].events;
    const second = rounds[1].events;
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.equal(first[0].event_name, 'beacon.security.sbom.inventory');
    assertSchema(first[0]);
    assertSchema(second[0]);
    assert.deepEqual(first[0].dependencies, second[0].dependencies);
    assert.notEqual(first[0].observed_at, second[0].observed_at);
    assert.equal(
      messages.filter(message => message.type === 'event').length,
      0
    );
  } finally {
    await worker.terminate();
  }
});

test('failed SBOM collection does not emit an empty replacement and can recover', async () => {
  const root = await mkdtemp(join(tmpdir(), 'beacon-inventory-failure-'));
  const output = join(root, 'application.cdx.json');
  await mkdir(output);
  const messages = [];
  const worker = new Worker(
    new URL('../src/sbom/worker.mjs', import.meta.url),
    {
      workerData: {
        identity,
        include: [root],
        output,
        localOutputEnabled: true,
        settings: { refreshSeconds: 300 },
      },
    }
  );
  worker.on('message', message => messages.push(message));
  try {
    worker.postMessage({ type: 'refresh' });
    await waitFor(() => messages.some(message => message.type === 'failure'));
    assert.equal(
      messages.filter(message => message.type === 'published').length,
      0
    );
    assert.equal(
      messages.filter(message => message.type === 'event').length,
      0
    );
    await rm(output, { recursive: true });
    worker.postMessage({ type: 'refresh' });
    await waitFor(() => messages.some(message => message.type === 'published'));
    assert.deepEqual(
      messages.find(message => message.type === 'published').events[0]
        .dependencies,
      []
    );
    assertSchema(
      messages.find(message => message.type === 'published').events[0]
    );
  } finally {
    await worker.terminate();
    await rm(root, { recursive: true, force: true });
  }
});

test('exporter sends only finding and inventory events', async () => {
  const logged = [];
  const exporter = new Exporter(identity);
  exporter.explicitLogger = {
    emit: event => logged.push(JSON.parse(event.body)),
  };
  try {
    assert.equal(
      exporter.emit({ event_name: 'beacon.security.export.dropped', count: 1 }),
      false
    );
    assert.equal(
      exporter.emit({
        event_name: 'beacon.security.finding.summary',
        count: 1,
      }),
      false
    );
    assert.equal(
      exporter.emit({
        event_name: 'beacon.security.sbom.inventory',
        instance_id: identity.instance_id,
        observed_at: '2026-10-27T09:20:00.000Z',
        started_at: '2026-10-27T09:00:00.000Z',
        uptime_ms: 1200000,
        dependencies: [],
      }),
      true
    );
    await waitFor(() => logged.length === 1);
    assert.equal(logged[0].schema_version, 2);
    assert.equal(logged[0].event_name, 'beacon.security.sbom.inventory');
    assert.deepEqual(logged[0].dependencies, []);
    assertSchema(logged[0]);
  } finally {
    await exporter.close();
  }
});
