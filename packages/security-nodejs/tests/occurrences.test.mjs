import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { logs } from '@opentelemetry/api-logs';
import {
  LoggerProvider,
  BatchLogRecordProcessor,
} from '@opentelemetry/sdk-logs';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

process.env.BEACON_SECURITY_ENABLED = 'true';
process.env.BEACON_SECURITY_NODE_INCLUDE = process.cwd();
process.env.BEACON_SECURITY_LOCAL_OUTPUT_ENABLED = 'false';
process.env.OTEL_LOGS_EXPORTER = 'none';
const { RuntimeLedger } = await import('../src/exporter/ledger.mjs');
const { Exporter } = await import('../src/exporter/index.mjs');
const { SecurityState } = await import('../src/core/state.mjs');
const { onlineEvent } = await import('../src/schema.mjs');
const identity = {
  application_id: 'occurrence-app',
  instance_id: '11111111-1111-4111-8111-111111111111',
  runtime: { language: 'javascript' },
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

function occurrence(ledger, index, location = 'query', fragment) {
  const state = new SecurityState(identity);
  ledger.begin(state);
  state.trace_id = index ? index.toString(16).padStart(32, '0') : '';
  state.server_span_id = index ? index.toString(16).padStart(16, '0') : '';
  const input =
    fragment === undefined
      ? undefined
      : 'SELECT * FROM users WHERE id=' + fragment;
  const marks = state
    .source(input || `input-${index}`, 'http.request.parameter', 'q')
    .map(mark => ({
      ...mark,
      start: input ? input.indexOf(fragment) : mark.start,
    }));
  try {
    const event = state.sink(
      'sql_injection',
      'template',
      'db.query',
      location,
      marks,
      input
    );
    assert.ok(event);
    assert.equal(
      state.sink(
        'sql_injection',
        'template',
        'db.query',
        location,
        marks,
        input
      ),
      null
    );
    assert.equal(state.pending.length, 1);
    const events = ledger.end(state);
    assert.equal(events.length, 1);
    assert.ok(event.sources.length);
    return events[0];
  } finally {
    state.close();
  }
}

test('each request retains its occurrence and trace when detail sampling suppresses the graph', () => {
  const ledger = new RuntimeLedger(identity, 'occurrences', '');
  const events = [1, 2, 0].map(index => occurrence(ledger, index));
  assert.equal(new Set(events.map(event => event.finding_id)).size, 1);
  assert.equal(new Set(events.map(event => event.occurrence_id)).size, 3);
  assert.ok(
    events.every(
      event => !Object.hasOwn(onlineEvent(event), 'occurrences_total')
    )
  );
  assert.deepEqual(
    events.map(event => event.evidence_sampled),
    [true, false, false]
  );
  assert.deepEqual(
    events.map(event => event.trace_id),
    ['1'.padStart(32, '0'), '2'.padStart(32, '0'), '']
  );
  for (const event of events.slice(1)) {
    assert.ok(event.occurrence_id);
    assert.equal(onlineEvent(event).truncated, undefined);
    for (const field of ['sources', 'propagation', 'ranges', 'stack'])
      assert.deepEqual(event[field], []);
  }
});

test('aggregation capacity does not suppress occurrence export', () => {
  const ledger = new RuntimeLedger(identity, 'capacity', '');
  ledger.maxFindings = 1;
  occurrence(ledger, 1);
  const event = occurrence(ledger, 2, 'another-query');
  assert.equal(event.aggregation_status, 'capacity_exceeded');
  assert.equal(event.evidence_sample_reason, 'finding_capacity');
  assert.equal(event.evidence_sampled, false);
  assert.equal(event.occurrences_total, undefined);
  assert.equal(event.trace_id, '2'.padStart(32, '0'));
  assert.equal(ledger.counts.finding_capacity_dropped, 1);
});

test('interleaved asynchronous requests retain independent IDs and context', async () => {
  const ledger = new RuntimeLedger(identity, 'async-occurrences', '');
  const events = await Promise.all(
    Array.from({ length: 12 }, async (_, index) => {
      await new Promise(resolve => setImmediate(resolve));
      return occurrence(ledger, index + 1);
    })
  );
  assert.equal(new Set(events.map(event => event.occurrence_id)).size, 12);
  assert.ok(
    events.every(
      event => !Object.hasOwn(onlineEvent(event), 'occurrences_total')
    )
  );
  assert.deepEqual(
    events.map(event => event.trace_id),
    Array.from({ length: 12 }, (_, i) => (i + 1).toString(16).padStart(32, '0'))
  );
});

for (const fragments of [undefined, ['12', '1 OR 1=1', '14']]) {
  test(`occurrences reach a real OTLP HTTP receiver (attack analysis: ${Boolean(fragments)})`, async () => {
    if (fragments) process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
    else delete process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT;
    const received = [];
    const server = http.createServer(async (request, response) => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      for (const resource of body.resourceLogs || [])
        for (const scope of resource.scopeLogs || [])
          received.push(...(scope.logRecords || []));
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const output = await mkdtemp(join(tmpdir(), 'security-occurrences-'));
    const provider = new LoggerProvider({
      processors: [
        new BatchLogRecordProcessor({
          exporter: new OTLPLogExporter({
            url: `http://127.0.0.1:${server.address().port}/v1/logs`,
          }),
        }),
      ],
    });
    logs.setGlobalLoggerProvider(provider);
    const exporter = new Exporter(identity, 'otlp-occurrences', output);
    try {
      await exporter.initialization;
      for (const index of [1, 2, 3])
        assert.equal(
          exporter.emit(
            occurrence(exporter.ledger, index, 'query', fragments?.[index - 1]),
            { evidence: true }
          ),
          true
        );
      await exporter.close(5000);
      await provider.forceFlush();
      const findings = received
        .map(log => ({ log, event: JSON.parse(log.body.stringValue) }))
        .filter(({ event }) => event.event_name === 'beacon.security.finding');
      assert.equal(
        findings.length,
        3,
        JSON.stringify({
          counters: exporter.counters,
          received: received.map(
            log => JSON.parse(log.body.stringValue).event_name
          ),
        })
      );
      for (const { event } of findings)
        assert.equal(
          validateEvent(event),
          true,
          ajv.errorsText(validateEvent.errors)
        );
      assert.equal(
        new Set(findings.map(({ event }) => event.finding_id)).size,
        1
      );
      assert.equal(
        new Set(findings.map(({ event }) => event.occurrence_id)).size,
        3
      );
      assert.deepEqual(
        findings.map(({ event }) => event.evidence_sampled),
        [true, Boolean(fragments), false]
      );
      if (fragments) {
        assert.deepEqual(
          findings.map(({ event }) => event.attack_evidence.status),
          ['no_evidence', 'suspected', 'no_evidence']
        );
        for (const { event } of findings)
          assert.equal(event.attack_evidence.outcome, undefined);
      }
      assert.deepEqual(
        findings.map(({ log }) => log.traceId.toLowerCase()),
        [1, 2, 3].map(i => i.toString(16).padStart(32, '0'))
      );
    } finally {
      await exporter.close(1000);
      await provider.shutdown();
      logs.disable();
      await new Promise(resolve => server.close(resolve));
      await rm(output, { recursive: true, force: true });
    }
  });
}
