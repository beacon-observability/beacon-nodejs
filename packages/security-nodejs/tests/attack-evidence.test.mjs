import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

process.env.BEACON_SECURITY_ENABLED = 'true';
process.env.BEACON_SECURITY_NODE_INCLUDE = process.cwd();
process.env.BEACON_SECURITY_LOCAL_OUTPUT_ENABLED = 'false';
const { analyze } = await import('../src/core/attack-evidence.mjs');
const { SecurityState } = await import('../src/core/state.mjs');
const { RuntimeLedger } = await import('../src/exporter/ledger.mjs');
const { profile } = await import('../src/config.mjs');
const { installLibrary } = await import('../src/adapters/sinks.mjs');
const { invoke } = await import('../src/core/calls.mjs');
const { bind } = await import('../src/core/runtime.mjs');
const { p } = await import('../src/core/values.mjs');
const cases = JSON.parse(
  await readFile(
    new URL('./fixtures/attack-analysis.json', import.meta.url),
    'utf8'
  )
);
const identity = {
  application_id: 'attack-app',
  instance_id: 'attack-instance',
  runtime: { language: 'javascript' },
};
function mark(value, input) {
  const start = value.indexOf(input);
  return {
    source_id: 'source',
    start,
    end: start + input.length,
    exact: true,
    unit: 'utf16_code_unit',
  };
}

for (const value of cases.sql)
  test(`ANSI SQL context: ${value.text}`, () => {
    process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
    const result = analyze('sql_injection', 'sql_template', value.text, [
      mark(value.text, value.input),
    ]);
    assert.equal(result.status, value.status);
    assert.equal(result.outcome, 'not_assessed');
    assert.equal(JSON.stringify(result).includes(value.text), false);
  });
for (const value of cases.shell)
  test(`POSIX shell context: ${value.text}`, () => {
    const result = analyze(
      'command_injection',
      'shell_script',
      value.text,
      [mark(value.text, value.input)],
      'sh'
    );
    assert.equal(result.status, value.status);
    assert.equal(result.outcome, 'not_assessed');
  });

test('unsupported dialects, units, imprecision, and budgets remain unknown', () => {
  delete process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT;
  const text = "SELECT 'guest'",
    taint = mark(text, 'guest');
  assert.equal(
    analyze('sql_injection', 'sql_template', text, [taint]).reason,
    'sql_dialect_unsupported'
  );
  process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
  for (const change of [
    { exact: false },
    { unit: 'byte' },
    { start: -1 },
    { end: null },
  ])
    assert.equal(
      analyze('sql_injection', 'sql_template', text, [{ ...taint, ...change }])
        .reason,
      'taint_imprecise'
    );
  for (const [value, marks] of [
    ['x'.repeat(8193), [taint]],
    [text, Array(65).fill(taint)],
  ])
    assert.equal(
      analyze('sql_injection', 'sql_template', value, marks).reason,
      'analysis_budget'
    );
  assert.equal(
    analyze(
      'command_injection',
      'shell_script',
      'echo guest',
      [taint],
      'cmd.exe'
    ).reason,
    'shell_dialect_unsupported'
  );
  assert.equal(
    analyze('sql_injection', 'sql_template', Buffer.from(text), [taint]).status,
    'unknown'
  );
  for (const [rule, role] of [
    ['ssrf', 'destination_address'],
    ['path_traversal', 'file_path'],
    ['command_execution', 'executable'],
  ])
    assert.equal(analyze(rule, role, 'guest', [taint]).status, 'unknown');
  assert.equal(
    analyze('http_request_input', 'path_or_query', 'guest', [taint]).status,
    'no_evidence'
  );
  assert.equal(
    analyze('command_execution', 'argument', 'guest', [taint]).status,
    'no_evidence'
  );
  const before = profile();
  process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'unknown';
  assert.notEqual(profile(), before);
});

function detect(state, fragment) {
  const query = 'SELECT * FROM users WHERE id=' + fragment;
  const marks = state
    .source(query, 'http.request.parameter', 'q')
    .map(mark => ({ ...mark, start: query.indexOf(fragment) }));
  return state.sink(
    'sql_injection',
    'template',
    'db.query',
    'query',
    marks,
    query
  );
}

test('same-request upgrades keep the occurrence ID and count once', () => {
  process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
  const ledger = new RuntimeLedger(identity, 'attack', '');
  const state = new SecurityState(identity);
  ledger.begin(state);
  try {
    const first = detect(state, '12');
    assert.equal(first.attack_evidence.status, 'no_evidence');
    const unknown = detect(state, 'customer_id');
    assert.equal(unknown.attack_evidence.status, 'unknown');
    assert.equal(detect(state, '14'), null);
    const upgrade = detect(state, '1 OR 1=1');
    assert.equal(upgrade.attack_evidence.status, 'suspected');
    assert.equal(first.evidence_id, unknown.evidence_id);
    assert.equal(first.evidence_id, upgrade.evidence_id);
    assert.equal(detect(state, '16'), null);
    assert.equal(state.pending.length, 1);
    const event = ledger.end(state)[0];
    assert.equal(event.occurrences_total, 1);
    assert.deepEqual(
      ledger.findings.get(event.finding_id).attack_evidence_counts,
      { unknown: 0, no_evidence: 0, suspected: 1 }
    );
  } finally {
    state.close();
  }
});

test('request evidence and strongest representative remain independent across intervals', t => {
  process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const ledger = new RuntimeLedger(identity, 'attack', '');
  const events = ['12', '1 OR 1=1', '14', 'customer_id', '16'].map(
    (fragment, index) => {
      if (index === 4) clock += ledger.sampleMillis + 1;
      const state = new SecurityState(identity);
      ledger.begin(state);
      state.trace_id = (index + 1).toString(16).padStart(32, '0');
      try {
        detect(state, fragment);
        return ledger.end(state)[0];
      } finally {
        state.close();
      }
    }
  );
  assert.deepEqual(
    events.map(e => e.attack_evidence.status),
    ['no_evidence', 'suspected', 'no_evidence', 'unknown', 'no_evidence']
  );
  assert.deepEqual(
    events.map(e => e.evidence_sampled),
    [true, true, false, false, true]
  );
  assert.equal(events[1].evidence_sample_reason, 'evidence_upgrade');
  assert.equal(new Set(events.map(e => e.finding_id)).size, 1);
  assert.equal(new Set(events.map(e => e.evidence_id)).size, 5);
  const finding = ledger.findings.get(events[0].finding_id);
  assert.deepEqual(finding.attack_evidence_counts, {
    unknown: 1,
    no_evidence: 3,
    suspected: 1,
  });
  assert.equal(finding.representative.trace_id, events[1].trace_id);
  assert.equal(finding.last_trace_id, events[4].trace_id);
  assert.equal(finding.strongest_attack_evidence.status, 'suspected');
  const snapshot = ledger.tick({}, { force: true, emitEvents: false });
  assert.deepEqual(
    snapshot.findings.findings[0].attack_evidence_counts,
    finding.attack_evidence_counts
  );
  for (const event of events)
    assert.equal(event.attack_evidence.outcome, 'not_assessed');
});

test('SQL adapter separates bound values from dynamic templates and does not invoke getters', () => {
  process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
  class Client {
    query(value) {
      return value;
    }
  }
  installLibrary('pg', { Client });
  const state = new SecurityState(identity),
    client = new Client();
  const query = 'SELECT * FROM users WHERE id=1 OR 1=1';
  const marks = state
    .source(query, 'http.request.parameter', 'q')
    .map(mark => ({ ...mark, start: query.indexOf('1 OR') }));
  const invokeQuery = (value, taint = []) =>
    invoke(
      { v: Client.prototype.query, receiver: p(client) },
      [p(value, taint)],
      'adapter#query'
    );
  try {
    bind(state, () => {
      const bound = {
        text: 'SELECT * FROM users WHERE id=$1',
        values: [query],
      };
      state.putField(bound, 'values', marks);
      invokeQuery(bound);
      assert.equal(state.pending.length, 0);
      const dynamic = { text: query, values: [] };
      state.putField(dynamic, 'text', marks);
      assert.equal(invokeQuery(dynamic).v, dynamic);
      assert.equal(state.pending[0].attack_evidence.status, 'suspected');
      let getters = 0;
      const unknown = {
        get text() {
          getters++;
          return query;
        },
      };
      state.putField(unknown, 'text', marks);
      invokeQuery(unknown);
      assert.equal(getters, 0);
      assert.equal(state.pending[0].attack_evidence.status, 'suspected');
    });
  } finally {
    state.close();
  }
});

test('process adapters analyze actual shell text and preserve application results', () => {
  const fake = {
    execSync(command) {
      return command;
    },
    spawnSync(file, argv) {
      return { file, argv, status: 0 };
    },
    execFileSync(file, argv) {
      return { file, argv };
    },
  };
  installLibrary('node:child_process', fake);
  const state = new SecurityState(identity);
  const call = (fn, args, location) =>
    invoke(
      { v: fn, receiver: p(fake) },
      args.map(([value, marks = []]) => p(value, marks)),
      location
    );
  try {
    bind(state, () => {
      const script = 'echo guest; id';
      const marks = state
        .source(script, 'http.request.parameter', 'q')
        .map(mark => ({ ...mark, start: script.indexOf('guest') }));
      assert.equal(call(fake.execSync, [[script, marks]], 'exec').v, script);
      assert.equal(
        state.pending.at(-1).attack_evidence.status,
        process.platform === 'win32' ? 'unknown' : 'suspected'
      );
      const argv = ['-c', script];
      state.putField(argv, '1', marks);
      call(fake.execFileSync, [['/bin/sh'], [argv]], 'explicit');
      assert.equal(
        state.pending.find(
          e => e.sink.location === 'explicit' && e.rule === 'command_injection'
        ).attack_evidence.status,
        'suspected'
      );
      const values = ['guest; id'];
      const argvMarks = state.source(values[0], 'http.request.parameter', 'q');
      state.putField(values, '0', argvMarks);
      const result = call(
        fake.spawnSync,
        [['echo'], [values], [{ shell: true }]],
        'joined'
      ).v;
      assert.equal(result.status, 0);
      const event = state.pending.find(e => e.sink.location === 'joined');
      assert.equal(
        event.attack_evidence.status,
        process.platform === 'win32' ? 'unknown' : 'suspected'
      );
      assert.equal(event.attack_evidence.outcome, 'not_assessed');
      call(fake.spawnSync, [['echo'], [values]], 'argv');
      assert.equal(
        state.pending.find(e => e.sink.location === 'argv').attack_evidence
          .status,
        'no_evidence'
      );
    });
  } finally {
    state.close();
  }
});
