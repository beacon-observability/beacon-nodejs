import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import {
  LoggerProvider,
  BatchLogRecordProcessor,
} from '@opentelemetry/sdk-logs';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';
import { Exporter } from '../src/exporter/index.mjs';

const identity = { application_id: 'priority', instance_id: 'priority' };
const finding = (id, status = 'no_evidence') => ({
  event_name: 'beacon.security.finding',
  finding_id: id,
  evidence_id: id,
  attack_evidence: { status, outcome: 'not_assessed' },
});

test('a real OTLP receiver gets stronger evidence after ordinary event capacity is exhausted', async () => {
  const received = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const envelope = JSON.parse(Buffer.concat(chunks).toString());
    for (const resource of envelope.resourceLogs || [])
      for (const scope of resource.scopeLogs || [])
        for (const log of scope.logRecords || [])
          received.push(JSON.parse(log.body.stringValue));
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const provider = new LoggerProvider({
    processors: [
      new BatchLogRecordProcessor({
        exporter: new OTLPLogExporter({
          url: `http://127.0.0.1:${server.address().port}/v1/logs`,
        }),
      }),
    ],
  });
  const exporter = new Exporter(identity, 'priority', '');
  exporter.explicitLogger = provider.getLogger('priority');
  const original = Date.now,
    fixed = Math.floor(Date.now() / 1000) * 1000 + 100;
  const drain = async () => {
    const started = performance.now();
    while (exporter.securityQueue.length || exporter.draining.security) {
      if (performance.now() - started > 5000) throw new Error('drain timeout');
      await new Promise(resolve => setTimeout(resolve, 1));
    }
  };
  try {
    Date.now = () => fixed;
    for (let i = 0; i < 100; i++) exporter.emit(finding('ordinary-' + i));
    await drain();
    exporter.emit(finding('priority-attack', 'suspected'));
    await drain();
    Date.now = original;
    await exporter.close(5000);
    await provider.forceFlush();
    assert.ok(received.some(event => event.evidence_id === 'priority-attack'));
    assert.ok(
      received.filter(event => event.evidence_id?.startsWith('ordinary-'))
        .length < 100
    );
  } finally {
    Date.now = original;
    await exporter.close(1000);
    await provider.shutdown();
    await new Promise(resolve => server.close(resolve));
  }
});

test('event and byte reservations retain bounded capacity for stronger evidence', async t => {
  const exporter = new Exporter(identity, 'priority', '');
  t.mock.method(Date, 'now', () => 1000000);
  try {
    let accepted = 0;
    for (let i = 0; i < 100; i++)
      if (
        exporter._withinBudget('security', 1, 100, 100000, finding(String(i)))
      )
        accepted++;
    assert.equal(accepted, 90);
    for (let i = 0; i < 10; i++)
      assert.equal(
        exporter._withinBudget(
          'security',
          1,
          100,
          100000,
          finding('attack', 'suspected')
        ),
        true
      );
    assert.equal(
      exporter._withinBudget(
        'security',
        1,
        100,
        100000,
        finding('overflow', 'suspected')
      ),
      false
    );
    exporter.budget.security = { second: 1000, events: 0, bytes: 0 };
    assert.equal(
      exporter._withinBudget('security', 900, 1000, 1000, finding('ordinary')),
      true
    );
    assert.equal(
      exporter._withinBudget(
        'security',
        1,
        1000,
        1000,
        finding('ordinary-overflow')
      ),
      false
    );
    assert.equal(
      exporter._withinBudget(
        'security',
        100,
        1000,
        1000,
        finding('attack', 'suspected')
      ),
      true
    );
    assert.equal(
      exporter._withinBudget(
        'security',
        1,
        1000,
        1000,
        finding('attack-overflow', 'suspected')
      ),
      false
    );
  } finally {
    await exporter.close(1000);
  }
});

test('full queues evict weaker entries and the real exporter emits stronger evidence first', async () => {
  const exporter = new Exporter(identity, 'priority', '');
  const emitted = [];
  exporter.explicitLogger = {
    emit(record) {
      emitted.push(JSON.parse(record.body));
    },
  };
  exporter.securityQueueSize = 3;
  // Hold only the drain admission while building a deterministic full queue.
  exporter.draining.security = true;
  try {
    assert.equal(exporter.emit(finding('ordinary-a')), true);
    assert.equal(exporter.emit(finding('ordinary-b')), true);
    assert.equal(exporter.emit(finding('ordinary-c')), true);
    assert.equal(exporter.emit(finding('attack', 'suspected')), true);
    assert.equal(exporter.emit(finding('ordinary-d')), false);
    exporter.draining.security = false;
    await exporter._drain('security');
    const findings = emitted.filter(
      event => event.event_name === 'beacon.security.finding'
    );
    assert.deepEqual(
      findings.map(event => event.evidence_id),
      ['attack', 'ordinary-b', 'ordinary-c']
    );
    assert.equal(exporter.counters['beacon.security.priority_evictions'], 1);
    assert.equal(exporter.counters['beacon.security.dropped.ordinary'], 2);
    assert.equal(
      exporter.counters['beacon.security.dropped.suspected'] ?? 0,
      0
    );
  } finally {
    exporter.draining.security = false;
    await exporter.close(1000);
  }
});
