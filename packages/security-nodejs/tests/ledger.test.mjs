import assert from 'node:assert/strict';
import test from 'node:test';

process.env.BEACON_SECURITY_NODE_INCLUDE = process.cwd();
process.env.BEACON_SECURITY_ENABLED = 'true';
const { RuntimeLedger } = await import('../src/exporter/ledger.mjs');
const { instrumentationEnabled, loaderCompatibility } = await import(
  '../src/config.mjs'
);

const identity = {
  application_id: 'node-ledger-test',
  instance_id: 'instance-ledger-test',
  service: { 'service.name': 'ledger-test' },
  code: { repository: 'repo', commit: 'commit', build_id: 'build' },
  runtime: { language: 'javascript', implementation: 'nodejs' },
  identity_status: 'configured',
};

function ledger() {
  return new RuntimeLedger(
    identity,
    'profile-test',
    '/tmp/security-node-ledger-test'
  );
}

test('collection gate immediately honors enable, loader, instrumentation and pause changes', () => {
  const value = ledger();
  try {
    assert.equal(value.enabled(), true);
    process.env.BEACON_SECURITY_ENABLED = 'false';
    assert.equal(value.enabled(), false);
    process.env.BEACON_SECURITY_ENABLED = 'true';
    loaderCompatibility(false);
    assert.equal(value.enabled(), false);
    loaderCompatibility(true);
    instrumentationEnabled(false);
    assert.equal(value.enabled(), false);
    instrumentationEnabled(true);
    assert.equal(value.enabled(), true);
    value.applyControl({ revision: 'pause', paused: true });
    assert.equal(value.enabled(), false);
    value.applyControl({ revision: 'resume', paused: false });
    assert.equal(value.enabled(), true);
  } finally {
    process.env.BEACON_SECURITY_ENABLED = 'true';
    loaderCompatibility(true);
    instrumentationEnabled(true);
  }
});

function state() {
  return {
    request: {
      method: 'GET',
      route: '/ledger/:id',
      route_status: 'matched',
      status_code: 200,
      started_at: '2026-09-08T04:00:00.000Z',
      ended_at: '2026-09-08T04:00:00.125Z',
      framework: 'express',
      transport: 'http',
      error_type: '',
    },
    trace_id: '0'.repeat(32),
    server_span_id: '1'.repeat(16),
    run: {},
    collection_enabled: true,
    collection_status: 'enabled',
    collection_generation: 0,
    truncated: false,
    pending: [],
    source_signatures: {},
    risk_source_signatures: {},
    sink_counts: {},
    source_count: 0,
    gaps: new Set(),
    gap(reason) {
      this.gaps.add(reason);
    },
  };
}

function runPolicy(runId = 'run-ledger-1') {
  return {
    run_id: runId,
    case_id: 'case-ledger',
    rule: 'sql_injection',
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    conditions: {
      suite: 'ledger-suite',
      fixture: 'ledger-fixture',
      expected_requests: 1,
    },
  };
}

test('control revisions drain runs and preserve CLI verification fields', () => {
  const value = ledger();
  value.applyControl({
    revision: 'revision-1',
    paused: false,
    run: runPolicy(),
  });
  assert.equal(value.appliedRevision, 'revision-1');

  const request = state();
  value.begin(request);
  assert.equal(request.run.run_id, 'run-ledger-1');
  assert.equal(request.collection_enabled, true);

  request.source_count = 1;
  request.source_signatures['http.request.parameter|query.id'] = 1;
  request.risk_source_signatures['http.request.parameter|query.id'] = 1;
  request.sink_counts.sql_injection = 1;
  request.pending.push({
    schema_version: 1,
    source: 'beacon_security',
    event_name: 'beacon.security.finding',
    evidence_id: 'evidence-ledger-1',
    finding_id: 'finding-ledger-1',
    rule: 'sql_injection',
    observed_at: new Date().toISOString(),
    trace_id: request.trace_id,
    server_span_id: request.server_span_id,
    sources: [{ type: 'http.request.parameter', name: 'query.id' }],
    sink: {
      function: 'query',
      role: 'sql_template',
      location: 'fixture#query',
      operation: '',
      path_role: '',
      input_part: '',
    },
  });

  const events = value.end(request);
  assert.equal(events.length, 1);
  assert.equal(events[0].occurrence_id, 'evidence-ledger-1');
  assert.equal(events[0].run.run_id, 'run-ledger-1');
  const expectedRequest = {
    method: 'GET',
    route: '/ledger/:id',
    route_status: 'matched',
    status_code: 200,
    started_at: '2026-09-08T04:00:00.000Z',
    ended_at: '2026-09-08T04:00:00.125Z',
    framework: 'express',
    transport: 'http',
    error_type: '',
  };
  assert.deepEqual(events[0].request, expectedRequest);

  const activeRun = value.runs.get('run-ledger-1');
  assert.equal(activeRun.requests, 1);
  assert.equal(activeRun.source_requests, 1);
  assert.equal(activeRun.sink_requests, 1);
  assert.equal(activeRun.observations, 1);
  assert.equal(activeRun.active_requests, 0);
  assert.equal(activeRun.finding_counts['finding-ledger-1'], 1);
  assert.equal(
    activeRun.risk_source_signatures['http.request.parameter|query.id'],
    1
  );

  value.applyControl({ revision: 'revision-2', paused: false, run: null });
  assert.equal(value.appliedRevision, 'revision-2');
  assert.equal(activeRun.status, 'closed');
  assert.equal(activeRun.active_requests, 0);

  const snapshot = value.tick({}, { force: true, emitEvents: false });
  const finding = snapshot.findings.findings.find(
    item => item.finding_id === 'finding-ledger-1'
  );
  assert.deepEqual(finding.request, expectedRequest);
  const savedRun = snapshot.runs.runs.find(
    item => item.run_id === 'run-ledger-1'
  );
  assert.deepEqual(savedRun.last_request, expectedRequest);
  assert.equal(savedRun.status, 'closed');
  assert.equal(savedRun.collection_enabled, true);
  assert.equal(savedRun.rule_enabled, true);

  value.tick(
    {},
    {
      control: { revision: 'revision-bad', paused: 'yes' },
      force: true,
      emitEvents: false,
    }
  );
  assert.equal(value.appliedRevision, 'revision-2');
  assert.equal(value.controlErrorRevision, 'revision-bad');
  assert.match(value.controlError, /invalid_pause/);
});

test('repeated findings retain samples and count every request across runs', t => {
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const value = ledger();
  const request = label => {
    const current = state();
    value.begin(current);
    current.source_signatures['http.request.parameter|query.id'] = 1;
    current.sink_counts.sql_injection = 1;
    const original = {
      event_name: 'beacon.security.finding',
      finding_id: 'repeated-finding',
      evidence_id: label,
      rule: 'sql_injection',
      observed_at: new Date(clock).toISOString(),
      trace_id: label === 'first' ? 'a'.repeat(32) : 'b'.repeat(32),
      sources: [
        { id: 'source-1', type: 'http.request.parameter', name: 'query.id' },
      ],
      propagation: [{ id: label, parents: ['source-1'] }],
      ranges: [{ start: 0, end: 4 }],
      stack: ['fixture#query'],
      sink: {
        function: 'query',
        role: 'sql_template',
        location: 'fixture#query',
      },
    };
    const saved = structuredClone(original);
    current.pending.push(original);
    const events = value.end(current);
    assert.deepEqual(original, saved);
    if (events.length)
      assert.deepEqual(events[0].propagation, original.propagation);
    return events;
  };
  assert.equal(request('first').length, 1);
  clock += 1000;
  assert.deepEqual(request('repeat'), []);
  const finding = value.tick({}, { force: true }).findings.findings[0];
  assert.equal(finding.occurrences, 2);
  assert.equal(finding.last_trace_id, 'b'.repeat(32));
  assert.equal(finding.representative.evidence_id, 'first');
  assert.deepEqual(finding.representative.propagation, [
    { id: 'first', parents: ['source-1'] },
  ]);
  value.applyControl({ revision: 'new-run', run: runPolicy('new-run') });
  assert.equal(request('new-run').length, 1);
  assert.deepEqual(request('in-run'), []);
  const run = value.tick({}, { force: true }).runs.runs[0];
  assert.equal(run.requests, 2);
  assert.equal(run.observations, 2);
  assert.equal(
    run.risk_source_signatures['http.request.parameter|query.id'],
    2
  );
  clock += value.sampleMillis + 1;
  assert.equal(request('after-interval').length, 1);
});

test('pause generation and active request budget are observable as incomplete', () => {
  const value = ledger();
  value.maxActive = 1;
  value.requestsPerSecond = 100;
  value.applyControl({ revision: 'revision-1', paused: false });

  const first = state();
  value.begin(first);
  assert.equal(first.collection_generation, 0);
  assert.equal(first.collection_enabled, true);

  const budgetSkipped = state();
  value.begin(budgetSkipped);
  assert.equal(budgetSkipped.collection_enabled, false);
  assert.equal(budgetSkipped.collection_status, 'budget_skipped');
  value.end(budgetSkipped);
  value.end(first);
  assert.equal(value.counts.requests_budget_skipped, 1);

  value.applyControl({ revision: 'revision-2', paused: true });
  assert.equal(value.pauseGeneration, 1);
  const paused = state();
  value.begin(paused);
  assert.equal(paused.collection_generation, 1);
  assert.equal(paused.collection_enabled, false);
  assert.equal(paused.collection_status, 'paused');
  value.end(paused);

  value.applyControl({ revision: 'revision-3', paused: false });
  assert.equal(value.pauseGeneration, 2);
  const inFlight = state();
  value.begin(inFlight);
  assert.equal(inFlight.collection_generation, 2);
  assert.equal(inFlight.collection_enabled, true);

  value.applyControl({ revision: 'revision-4', paused: true });
  const incomplete = value.end(inFlight);
  assert.ok(inFlight.gaps.has('collection_paused_during_request'));
  assert.equal(
    incomplete[0].event_name,
    'beacon.security.collection.incomplete'
  );
  assert.ok(
    incomplete[0].coverage_gaps.includes('collection_paused_during_request')
  );

  value.applyControl({ revision: 'revision-5', paused: false });
  const health = value.health({ security_dropped: 0 });
  assert.equal(health.control_revision, 'revision-5');
  assert.equal(health.status, 'incomplete');
  assert.ok(health.counts.requests_incomplete >= 1);
  assert.ok(health.counts.requests_paused >= 1);
});

test('run snapshots remain stable across updates and counter retention is bounded across runs', () => {
  const value = ledger();
  value.maxRunCounterBytes = 512;
  value.applyControl({ revision: 'start-old', run: runPolicy('old') });
  const complete = signature => {
    const request = state();
    value.begin(request);
    request.source_signatures[signature] = 1;
    value.end(request);
  };
  complete('old-source');
  value.applyControl({ revision: 'start-new', run: runPolicy('new') });
  complete('new-source');
  const first = value.tick({}, { force: true });
  value.writtenRevisions.runs = first.revisions.runs;
  complete('new-source');
  const second = value.tick({}, { force: true });
  assert.equal(first.runs.runs[0], second.runs.runs[0]);
  assert.equal(first.runs.runs[1].source_signatures['new-source'], 1);
  assert.equal(second.runs.runs[1].source_signatures['new-source'], 2);
  for (let i = 0; i < 20; i++) complete('extra-' + i);
  const snapshot = value.tick({}, { force: true }).runs.runs;
  assert.equal(snapshot[0].source_signatures['old-source'], 1);
  assert.equal(snapshot[1].source_signatures['new-source'], 2);
  assert.ok(snapshot[1].incomplete_requests > 0);
  assert.ok(value.runCounterBytes <= 512);
  assert.equal(value.health().status, 'incomplete');
});
