import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test, { after } from 'node:test';

// The exporter gates collection on the configured include root and supported
// Node line. The OrbStack command supplies this before importing config.mjs.
process.env.BEACON_SECURITY_NODE_INCLUDE = process.cwd();
process.env.BEACON_SECURITY_ENABLED = 'true';
process.env.BEACON_SECURITY_LOCAL_OUTPUT_ENABLED = 'true';
delete process.env.BEACON_SECURITY_CONTROL_FILE;
delete process.env.BEACON_SECURITY_EVIDENCE_FILE;

const { Exporter } = await import('../src/exporter/index.mjs');

const execFile = promisify(execFileCallback);
const securityctl = resolve(
  dirname(fileURLToPath(import.meta.url)),
  'fixtures/securityctl.py'
);
const results = [];
const emitted = [];
// Node 22 can exit a test worker while only the Exporter's intentionally
// unref'd I/O worker is waiting for a message. Keep this test process alive
// until its asynchronous exporter checks have settled.
const testKeepAlive = setInterval(() => {}, 1000);
globalThis.__BEACON_SECURITY_LOGGER__ = {
  emit(record) {
    emitted.push(record);
  },
};

const identity = {
  application_id: 'node-controls-test',
  instance_id: 'instance-controls-test',
  service: { 'service.name': 'node-controls-test' },
  code: { repository: 'repo', commit: 'commit', build_id: 'build' },
  runtime: { language: 'javascript', implementation: 'nodejs' },
  identity_status: 'configured',
};
const profile = 'profile-controls-test';

function event(id = 'evidence-controls-1') {
  return {
    schema_version: 1,
    source: 'beacon_security',
    event_name: 'beacon.security.finding',
    evidence_id: id,
    finding_id: `finding-${id}`,
    rule: 'sql_injection',
    observed_at: new Date().toISOString(),
    trace_id: 'a'.repeat(32),
    server_span_id: 'b'.repeat(16),
    current_span_id: 'c'.repeat(16),
    trace_flags: 1,
    sources: [{ type: 'http.request.parameter', name: 'query.id' }],
    sink: {
      function: 'query',
      role: 'sql_template',
      location: 'controls.test#query',
      operation: '',
      path_role: '',
      input_part: '',
    },
  };
}

function requestState() {
  return {
    request: { method: 'GET', route: '/controls', status_code: 200 },
    trace_id: 'a'.repeat(32),
    server_span_id: 'b'.repeat(16),
    trace_flags: 1,
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

async function waitFor(predicate, label, timeoutMillis = 10_000) {
  const deadline = Date.now() + timeoutMillis;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise(resolveValue => setTimeout(resolveValue, 20));
  }
  throw new Error(`timeout:${label}`);
}

async function outputDirectory(label) {
  return mkdtemp(join(tmpdir(), `BeaconSecurity-controls-${label}-`));
}

async function closeExporter(exporter) {
  await exporter.close(1_500);
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function cli(output, args) {
  const { stdout } = await execFile(
    'python3',
    [securityctl, '--dir', output, ...args],
    {
      encoding: 'utf8',
      timeout: 20_000,
    }
  );
  return JSON.parse(stdout);
}

async function cliExpectExit(output, args, expectedCode) {
  try {
    await execFile('python3', [securityctl, '--dir', output, ...args], {
      encoding: 'utf8',
      timeout: 20_000,
    });
  } catch (error) {
    assert.equal(error.code, expectedCode);
    return JSON.parse(error.stdout);
  }
  assert.fail(
    `securityctl unexpectedly exited successfully: ${args.join(' ')}`
  );
}

after(async () => {
  clearInterval(testKeepAlive);
  const resultPath = process.env.CONTROLS_RESULT_PATH;
  if (!resultPath) return;
  await mkdir(dirname(resultPath), { recursive: true });
  await writeFile(
    resultPath,
    `${JSON.stringify({ node: process.version, results }, null, 2)}\n`
  );
});

test('Exporter drops on bounded queue overflow without blocking the caller', async () => {
  const output = await outputDirectory('queue');
  const exporter = new Exporter(identity, profile, output);
  try {
    await exporter.initialization;
    exporter.securityQueueSize = 1;
    exporter.draining.security = true;
    const original = { ...event('queue-1'), payload: { marker: 'before' } };
    assert.equal(exporter.emit(original), true);
    original.payload.marker = 'after';
    assert.equal(exporter.emit(event('queue-2')), false);
    exporter.draining.security = false;
    await exporter._drain('security');
    await waitFor(() => !exporter.draining.security, 'queue drain');

    assert.equal(exporter.counters['beacon.security.queue_full'], 1);
    assert.equal(exporter.ledger.counts.delivery_loss, 1);
    assert.equal(exporter.delivery().security_queue_depth, 0);
    assert.ok(exporter.ledger.health(exporter.delivery()).delivery_loss >= 1);
    const sent = emitted
      .map(record => JSON.parse(String(record.body)))
      .find(item => item.evidence_id === 'queue-1');
    assert.equal(sent.payload.marker, 'before');
    results.push({
      check: 'queue-overflow',
      queue_full: exporter.counters['beacon.security.queue_full'],
      delivery_loss: exporter.ledger.counts.delivery_loss,
      dropped: exporter.delivery().dropped,
    });
  } finally {
    await closeExporter(exporter);
    await rm(output, { recursive: true, force: true });
  }
});

test('Exporter separates SBOM log sources through normal and truncated delivery', async () => {
  const output = await outputDirectory('sbom-source');
  const exporter = new Exporter(identity, profile, output);
  try {
    await exporter.initialization;
    for (const maxBytes of [65536, 256, 128]) {
      exporter.maxBytes = maxBytes;
      for (const [eventName, source] of [
        ['beacon.security.finding', 'beacon_security'],
        ['beacon.security.sbom.snapshot', 'beacon_security_sbom'],
        ['beacon.security.sbom.health', 'beacon_security_sbom'],
        ['beacon.security.sbom.update_failed', 'beacon_security_sbom'],
        ['beacon.security.sbom.export.dropped', 'beacon_security_sbom'],
      ]) {
        const start = emitted.length;
        assert.equal(
          exporter.emit({
            event_name: eventName,
            source: 'caller-override',
            sbom_id: 'source-test',
            payload: 'x'.repeat(4096),
          }),
          true
        );
        await waitFor(() => emitted.length > start, 'source routing log');
        const log = emitted[start];
        const body = JSON.parse(String(log.body));
        assert.equal(log.attributes.source, source);
        assert.equal(body.source, source);
        assert.equal(log.eventName, body.event_name);
        assert.equal(log.attributes['event.name'], body.event_name);
        assert.ok(Buffer.byteLength(log.body) <= maxBytes);
        if (maxBytes === 65536) assert.equal(body.event_name, eventName);
        else {
          assert.equal(body.event_name, 'beacon.security.export.truncated');
          assert.equal(
            body.original_event,
            maxBytes === 256 ? eventName : undefined
          );
        }
      }
    }
  } finally {
    await closeExporter(exporter);
  }
});

test('Exporter enforces UTF-8 byte budgets and keeps truncation events canonical', async () => {
  const output = await outputDirectory('utf8-budget');
  const previousEvidence = process.env.BEACON_SECURITY_EVIDENCE_FILE;
  process.env.BEACON_SECURITY_EVIDENCE_FILE = join(output, 'evidence.jsonl');
  const exporter = new Exporter(identity, profile, output);
  delete process.env.BEACON_SECURITY_EVIDENCE_FILE;
  try {
    await exporter.initialization;
    exporter.maxBytes = 256;
    const oversized = { ...event('utf8-budget'), payload: 'é'.repeat(512) };
    const original = structuredClone(oversized);
    const encoded = exporter._encodeRecord(oversized);
    assert.deepEqual(oversized, original);
    assert.ok(Buffer.isBuffer(encoded.bytes));
    assert.equal(
      encoded.bytes.byteLength,
      Buffer.byteLength(encoded.bytes.toString('utf8'))
    );
    assert.ok(encoded.bytes.byteLength <= exporter.maxBytes);
    assert.equal(encoded.event.event_name, 'beacon.security.export.truncated');
    assert.equal(encoded.event.schema_version, 1);
    assert.equal(encoded.event.source, 'beacon_security');

    assert.equal(exporter.emit(oversized, { evidence: true }), true);
    await waitFor(
      () => (exporter.counters['beacon.security.file_written'] || 0) >= 1,
      'utf8 truncation write'
    );
    const captured = emitted.find(record => {
      try {
        return JSON.parse(String(record.body)).evidence_id === 'utf8-budget';
      } catch {
        return false;
      }
    });
    assert.ok(captured);
    const capturedBody = JSON.parse(String(captured.body));
    assert.equal(captured.eventName, capturedBody.event_name);
    assert.equal(captured.attributes['event.name'], capturedBody.event_name);
    assert.equal(captured.attributes.source, 'beacon_security');
    assert.equal(capturedBody.source, 'beacon_security');
    assert.equal(capturedBody.event_name, encoded.event.event_name);
    const { trace } = await import('@opentelemetry/api');
    const capturedSpan = trace.getSpanContext(captured.context);
    assert.equal(capturedSpan.traceId, oversized.trace_id);
    assert.equal(capturedSpan.spanId, oversized.server_span_id);
    assert.equal(capturedSpan.traceFlags, oversized.trace_flags);

    exporter.securityBytesPerSecond = encoded.bytes.byteLength - 1;
    const dropped = { ...oversized, evidence_id: 'utf8-budget-drop' };
    assert.equal(exporter.emit(dropped, { evidence: true }), true);
    await waitFor(
      () => (exporter.counters['beacon.security.budget_exceeded'] || 0) >= 1,
      'utf8 budget drop'
    );
    assert.equal(exporter.counters['beacon.security.file_written'], 1);
    results.push({
      check: 'utf8-byte-budget',
      encoded_bytes: encoded.bytes.byteLength,
      budget_bytes: exporter.securityBytesPerSecond,
      budget_exceeded: exporter.counters['beacon.security.budget_exceeded'],
      security_dropped: exporter.delivery().security_dropped,
      captured_log: {
        event_name: captured.eventName,
        body_event_name: capturedBody.event_name,
        source: captured.attributes.source,
        trace_id: capturedSpan.traceId,
        span_id: capturedSpan.spanId,
        trace_flags: capturedSpan.traceFlags,
      },
    });
  } finally {
    await closeExporter(exporter);
    if (previousEvidence === undefined)
      delete process.env.BEACON_SECURITY_EVIDENCE_FILE;
    else process.env.BEACON_SECURITY_EVIDENCE_FILE = previousEvidence;
    await rm(output, { recursive: true, force: true });
  }
});

test('SBOM rate limiting defers queued snapshots while security events keep flowing', async () => {
  const output = await outputDirectory('sbom-deferred');
  const exporter = new Exporter(identity, profile, output);
  try {
    await exporter.initialization;
    exporter.sbomEventsPerSecond = 1;
    for (let index = 0; index < 3; index++) {
      exporter.emit({
        event_name: 'beacon.security.sbom.snapshot',
        sbom_id: 'deferred-fixture',
        revision: index,
        dependencies: [{ name: 'pkg', version: '1' }],
      });
    }
    await waitFor(
      () => exporter.counters['beacon.security.sbom.budget_deferred'] > 0,
      'sbom waiting for budget'
    );
    exporter.emit(event('during-sbom-deferral'));
    await waitFor(
      () =>
        emitted.some(
          record =>
            JSON.parse(record.body).evidence_id === 'during-sbom-deferral'
        ),
      'independent security queue'
    );
    await waitFor(
      () =>
        emitted.filter(
          record => JSON.parse(record.body).sbom_id === 'deferred-fixture'
        ).length === 3,
      'all snapshots delivered',
      4000
    );
    assert.equal(exporter.delivery().sbom_dropped, 0);
    assert.equal(exporter.delivery().security_dropped, 0);
    assert.equal(exporter.ledger.counts.delivery_loss || 0, 0);
  } finally {
    await closeExporter(exporter);
    assert.equal(exporter.sbomResumeTimer, null);
    await rm(output, { recursive: true, force: true });
  }
});

test('Exporter records evidence output failure while OTel API delivery remains observable', async () => {
  const output = await outputDirectory('output-failure');
  // A directory is a valid parent for worker initialization but an invalid
  // append target, giving a deterministic output failure without permissions.
  process.env.BEACON_SECURITY_EVIDENCE_FILE = output;
  const exporter = new Exporter(identity, profile, output);
  delete process.env.BEACON_SECURITY_EVIDENCE_FILE;
  try {
    await exporter.initialization;
    assert.equal(exporter.workerFailed, null);
    assert.equal(
      exporter.emit(event('output-failure'), { evidence: true }),
      true
    );
    await waitFor(() => !exporter.draining.security, 'output failure drain');

    assert.ok((exporter.counters['beacon.security.file_failed'] || 0) >= 1);
    assert.ok((exporter.ledger.counts.delivery_failure || 0) >= 1);
    assert.ok(exporter.delivery().last_otel_api_call_at);
    assert.ok(exporter.ledger.health(exporter.delivery()).delivery_loss >= 1);
    results.push({
      check: 'output-failure',
      file_failed: exporter.counters['beacon.security.file_failed'],
      delivery_failure: exporter.ledger.counts.delivery_failure,
      otel_api_calls:
        exporter.counters['beacon.security.otel_api_emitted'] || 0,
      delivery_loss: exporter.ledger.health(exporter.delivery()).delivery_loss,
    });
  } finally {
    await closeExporter(exporter);
    await rm(output, { recursive: true, force: true });
  }
});

test('Exporter surfaces an actual I/O worker fault and snapshot loss', async () => {
  const output = await outputDirectory('worker-failure');
  const exporter = new Exporter(identity, profile, output);
  try {
    await exporter.initialization;
    assert.ok(exporter.worker);
    await exporter.worker.terminate();
    await waitFor(() => Boolean(exporter.workerFailed), 'worker failure');

    await exporter._tick(true);
    assert.match(exporter.ledger.controlError, /io_worker|worker/i);
    assert.equal(exporter.ledger.controlErrorRevision, 'unparsed');
    assert.ok(exporter.ledger.snapshotFailures >= 1);
    results.push({
      check: 'io-worker-failure',
      worker_error: exporter.workerFailed.message,
      control_error: exporter.ledger.controlError,
      snapshot_failures: exporter.ledger.snapshotFailures,
    });
  } finally {
    await closeExporter(exporter);
    await rm(output, { recursive: true, force: true });
  }
});

test('snapshot writes preserve concurrent updates and skip unchanged findings', async () => {
  const output = await outputDirectory('snapshot-concurrency');
  const exporter = new Exporter(identity, profile, output);
  clearInterval(exporter.monitor);
  const original = exporter._ioRequest.bind(exporter);
  let release;
  try {
    await exporter._tick(true);
    const complete = () => {
      const state = {
        request: {},
        pending: [
          {
            finding_id: 'snapshot-finding',
            evidence_id: 'snapshot-evidence',
            event_name: 'beacon.security.finding',
            rule: 'sql_injection',
            observed_at: new Date().toISOString(),
            sources: [],
            propagation: [{ id: 1, operation: 'source' }],
          },
        ],
        collection_enabled: true,
        collection_generation: 0,
      };
      exporter.ledger.begin(state);
      exporter.ledger.end(state);
    };
    complete();
    let entered;
    const started = new Promise(resolve => {
      entered = resolve;
    });
    const blocked = new Promise(resolve => {
      release = resolve;
    });
    let once = true;
    exporter._ioRequest = async (operation, ...args) => {
      if (operation === 'snapshot-row' && once) {
        once = false;
        entered();
        await blocked;
      }
      return original(operation, ...args);
    };
    const first = exporter._tick(true);
    await started;
    complete();
    release();
    await first;
    const filename = join(output, 'findings.json');
    assert.equal(
      JSON.parse(await readFile(filename, 'utf8')).findings[0].occurrences,
      1
    );
    await exporter._tick(true);
    const saved = await readFile(filename, 'utf8');
    assert.equal(JSON.parse(saved).findings[0].occurrences, 2);
    let findingWrites = 0;
    exporter._ioRequest = (operation, value, ...args) => {
      if (operation === 'snapshot-begin' && value.key === 'findings')
        findingWrites++;
      return original(operation, value, ...args);
    };
    await exporter._tick(true);
    assert.equal(findingWrites, 0);
    assert.equal(await readFile(filename, 'utf8'), saved);
    complete();
    let failCommit = true;
    exporter._ioRequest = (operation, ...args) => {
      if (operation === 'snapshot-commit' && failCommit) {
        failCommit = false;
        return Promise.reject(new Error('snapshot write failed'));
      }
      return original(operation, ...args);
    };
    await exporter._tick(true);
    assert.equal(await readFile(filename, 'utf8'), saved);
    await exporter._tick(true);
    assert.equal(
      JSON.parse(await readFile(filename, 'utf8')).findings[0].occurrences,
      3
    );
  } finally {
    release?.();
    exporter._ioRequest = original;
    await closeExporter(exporter);
    await rm(output, { recursive: true, force: true });
  }
});

test('CLI controls run start/stop drain, pause/resume, revision rejection, and verify', async () => {
  const output = await outputDirectory('controls');
  const previousEvidence = process.env.BEACON_SECURITY_EVIDENCE_FILE;
  process.env.BEACON_SECURITY_EVIDENCE_FILE = join(output, 'evidence.jsonl');
  const exporter = new Exporter(identity, profile, output);
  delete process.env.BEACON_SECURITY_EVIDENCE_FILE;
  try {
    await exporter.initialization;
    await exporter._tick(true);

    const started = await cli(output, [
      'run-start',
      '--case',
      'case-controls',
      '--rule',
      'sql_injection',
      '--suite',
      'controls-suite',
      '--fixture',
      'controls-fixture',
      '--expected-requests',
      '1',
      '--ttl',
      '300',
    ]);
    assert.match(started.run_id, /^run-/);
    await waitFor(
      () => exporter.ledger.policy.run?.run_id === started.run_id,
      'run start apply'
    );

    const request = requestState();
    exporter.ledger.begin(request);
    request.source_count = 1;
    request.source_signatures['http.request.parameter|query.id'] = 1;
    request.risk_source_signatures['http.request.parameter|query.id'] = 1;
    request.sink_counts.sql_injection = 1;
    request.pending.push(event('controls-run'));
    const events = exporter.ledger.end(request);
    assert.equal(events.length, 1);
    for (const value of events) exporter.emit(value, { evidence: true });
    await waitFor(() => !exporter.draining.security, 'run evidence drain');
    await exporter._tick(true);

    const stopped = await cli(output, ['run-stop']);
    assert.equal(stopped.run_id, started.run_id);
    assert.equal(stopped.status, 'closed');

    const paused = await cli(output, ['pause']);
    assert.equal(paused.status, 'paused');
    assert.equal(paused.collection_status, 'paused');
    const resumed = await cli(output, ['resume']);
    assert.notEqual(resumed.status, 'paused');
    assert.notEqual(resumed.collection_status, 'paused');

    const appliedRevision = exporter.ledger.appliedRevision;
    await writeJson(join(output, 'control.json'), {
      revision: 'revision-invalid',
      paused: 'invalid',
    });
    await exporter._tick(true);
    const rejected = exporter.ledger.health(exporter.delivery());
    assert.equal(rejected.control_revision, appliedRevision);
    assert.equal(rejected.control_error_revision, 'revision-invalid');
    assert.match(rejected.control_error, /invalid_pause/);

    const finalControl = {
      revision: 'revision-final',
      paused: false,
      run: null,
    };
    await writeJson(join(output, 'control.json'), finalControl);
    await exporter._tick(true);
    assert.equal(exporter.ledger.appliedRevision, 'revision-final');

    const runs = await readJson(join(output, 'runs.json'));
    const closedRun = runs.runs.find(value => value.run_id === started.run_id);
    assert.equal(closedRun.status, 'closed');
    assert.equal(closedRun.active_requests, 0);
    assert.equal(closedRun.observations, 1);
    assert.equal(closedRun.source_requests, 1);
    assert.equal(closedRun.sink_requests, 1);

    const queried = await cli(output, [
      'query',
      'runs',
      '--run',
      started.run_id,
    ]);
    assert.equal(queried.total, 1);
    const status = await cli(output, ['status']);
    assert.equal(status.control_revision, 'revision-final');

    const baselinePath = join(output, 'baseline-run.json');
    const candidatePath = join(output, 'candidate-run.json');
    const verifyPath = join(output, 'controls-verify.json');
    await writeJson(baselinePath, closedRun);
    await writeJson(candidatePath, closedRun);
    const verified = await cli(output, [
      'verify',
      '--baseline',
      baselinePath,
      '--candidate',
      candidatePath,
      '--output',
      verifyPath,
    ]);
    assert.equal(verified.outcome, 'observed');
    assert.equal((await readJson(verifyPath)).outcome, 'observed');

    const incompleteStarted = await cli(output, [
      'run-start',
      '--case',
      'case-controls',
      '--rule',
      'sql_injection',
      '--suite',
      'controls-suite',
      '--fixture',
      'controls-fixture',
      '--expected-requests',
      '1',
      '--ttl',
      '300',
    ]);
    await waitFor(
      () => exporter.ledger.policy.run?.run_id === incompleteStarted.run_id,
      'incomplete run start apply'
    );
    const incompleteRequest = requestState();
    exporter.ledger.begin(incompleteRequest);
    incompleteRequest.source_count = 1;
    incompleteRequest.source_signatures['http.request.parameter|query.id'] = 1;
    incompleteRequest.risk_source_signatures[
      'http.request.parameter|query.id'
    ] = 1;
    incompleteRequest.sink_counts.sql_injection = 1;
    incompleteRequest.gap('fixture_state_gap');
    const incompleteEvents = exporter.ledger.end(incompleteRequest);
    assert.ok(
      incompleteEvents.some(
        value => value.event_name === 'beacon.security.collection.incomplete'
      )
    );
    for (const value of incompleteEvents)
      exporter.emit(value, { evidence: true });
    await waitFor(
      () => !exporter.draining.security,
      'incomplete run evidence drain'
    );
    await exporter._tick(true);
    const incompletePath = join(output, 'incomplete-run.json');
    const incompleteStopped = await cli(output, [
      'run-stop',
      '--output',
      incompletePath,
    ]);
    assert.equal(incompleteStopped.status, 'closed');
    assert.ok(incompleteStopped.incomplete_requests >= 1);
    const inconclusivePath = join(output, 'controls-inconclusive.json');
    const inconclusive = await cliExpectExit(
      output,
      [
        'verify',
        '--baseline',
        baselinePath,
        '--candidate',
        incompletePath,
        '--output',
        inconclusivePath,
      ],
      3
    );
    assert.equal(inconclusive.outcome, 'inconclusive');
    assert.ok(inconclusive.reasons.includes('candidate_incomplete_requests'));
    assert.ok(
      !inconclusive.reasons.some(reason =>
        /mismatched_or_missing_(case_id|conditions)/.test(reason)
      )
    );
    assert.equal((await readJson(inconclusivePath)).outcome, 'inconclusive');

    const evidenceRecords = (
      await readFile(join(output, 'evidence.jsonl'), 'utf8')
    )
      .split('\n')
      .filter(Boolean)
      .map(line => JSON.parse(line));
    const evidenceSample = evidenceRecords.find(
      value => value.event_name === 'beacon.security.finding'
    );
    assert.ok(evidenceSample);

    results.push({
      check: 'controls-and-cli',
      run_id: started.run_id,
      stopped_status: stopped.status,
      pause_status: paused.status,
      resume_status: resumed.status,
      rejected_revision: rejected.control_error_revision,
      rejected_error: rejected.control_error,
      queried_runs: queried.total,
      verify_outcome: verified.outcome,
      incomplete_run_id: incompleteStopped.run_id,
      incomplete_requests: incompleteStopped.incomplete_requests,
      inconclusive_verify_outcome: inconclusive.outcome,
      inconclusive_verify_exit: 3,
      inconclusive_verify_reasons: inconclusive.reasons,
      run: {
        requests: closedRun.requests,
        source_requests: closedRun.source_requests,
        sink_requests: closedRun.sink_requests,
        observations: closedRun.observations,
        delivery_loss: closedRun.delivery_loss,
      },
      evidence_sample: evidenceSample,
    });
  } finally {
    await closeExporter(exporter);
    if (previousEvidence === undefined)
      delete process.env.BEACON_SECURITY_EVIDENCE_FILE;
    else process.env.BEACON_SECURITY_EVIDENCE_FILE = previousEvidence;
    await rm(output, { recursive: true, force: true });
  }
});

test('run worker cache preserves concurrent counter updates and retries failed commits', async () => {
  const output = await outputDirectory('run-cache');
  const exporter = new Exporter(identity, profile, output);
  clearInterval(exporter.monitor);
  const original = exporter._ioRequest.bind(exporter);
  let release;
  try {
    await exporter._tick(true);
    const policy = run_id => ({
      run_id,
      case_id: 'cache',
      rule: 'sql_injection',
      expires_at: new Date(Date.now() + 60000).toISOString(),
      conditions: { suite: 'cache', fixture: 'cache', expected_requests: 1 },
    });
    const complete = () => {
      const state = requestState();
      exporter.ledger.begin(state);
      state.source_signatures.query = 1;
      exporter.ledger.end(state);
    };
    exporter.ledger.applyControl({ revision: 'old-run', run: policy('old') });
    complete();
    exporter.ledger.applyControl({ revision: 'new-run', run: policy('new') });
    complete();
    await exporter._tick(true);
    complete();
    let entered;
    const started = new Promise(resolve => {
      entered = resolve;
    });
    const blocked = new Promise(resolve => {
      release = resolve;
    });
    const messages = [];
    exporter._ioRequest = async (operation, value) => {
      if (operation === 'snapshot-row') {
        messages.push(value);
        if (value.record?.run_id === 'new') {
          entered();
          await blocked;
        }
      }
      return original(operation, value);
    };
    const pending = exporter._tick(true);
    await started;
    complete();
    release();
    await pending;
    assert.ok(messages.some(value => value.runId === 'old'));
    assert.ok(!messages.some(value => value.record?.run_id === 'old'));
    const filename = join(output, 'runs.json');
    assert.equal((await readJson(filename)).runs[1].source_signatures.query, 2);
    let fail = true;
    exporter._ioRequest = (operation, value) => {
      if (operation === 'snapshot-commit' && fail) {
        fail = false;
        throw new Error('run commit failed');
      }
      return original(operation, value);
    };
    await exporter._tick(true);
    assert.equal((await readJson(filename)).runs[1].source_signatures.query, 2);
    await exporter._tick(true);
    const saved = (await readJson(filename)).runs;
    assert.equal(saved[0].source_signatures.query, 1);
    assert.equal(saved[1].source_signatures.query, 3);
  } finally {
    release?.();
    exporter._ioRequest = original;
    await closeExporter(exporter);
    await rm(output, { recursive: true, force: true });
  }
});
