import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

process.env.BEACON_SECURITY_ENABLED = 'true';
process.env.BEACON_SECURITY_NODE_INCLUDE = process.cwd();
process.env.BEACON_SECURITY_LOCAL_OUTPUT_ENABLED = 'false';
process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
const { Exporter } = await import('../src/exporter/index.mjs');
const { SecurityState } = await import('../src/core/state.mjs');
const identity = {
  application_id: 'export-policy',
  instance_id: '11111111-1111-4111-8111-111111111111',
  runtime: { language: 'javascript' },
};
const key = 'BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED';

for (const setting of [undefined, 'false', 'invalid', 'true']) {
  test(`export policy covers OTel, JSONL, and queue admission (${setting})`, async () => {
    const original = process.env[key];
    if (setting === undefined) delete process.env[key];
    else process.env[key] = setting;
    const output = await mkdtemp(join(tmpdir(), 'security-export-policy-'));
    const file = join(output, 'evidence.jsonl');
    process.env.BEACON_SECURITY_EVIDENCE_FILE = file;
    const keepAlive = setInterval(() => {}, 1000);
    const exporter = new Exporter(identity, 'policy', output);
    const logged = [];
    exporter.explicitLogger = {
      emit: record => logged.push(JSON.parse(record.body)),
    };
    try {
      for (const status of ['no_evidence', 'unknown', 'suspected']) {
        assert.equal(
          exporter.emit(
            {
              event_name: 'beacon.security.finding',
              occurrence_id: status,
              attack_evidence: { status, reason: 'test' },
            },
            { evidence: true }
          ),
          status !== 'no_evidence' || setting === 'true'
        );
      }
      assert.equal(
        exporter.emit({
          event_name: 'beacon.security.sbom.inventory',
          dependencies: [],
          started_at: '2026-11-02T00:00:00Z',
          uptime_ms: 1000,
        }),
        true
      );
      await exporter.close();
      const expected = ['unknown', 'suspected'];
      if (setting === 'true') expected.push('no_evidence');
      assert.deepEqual(
        logged
          .filter(e => e.occurrence_id)
          .map(e => e.occurrence_id)
          .sort(),
        expected.sort()
      );
      assert.equal(logged.length, expected.length + 1);
      const records = (await readFile(file, 'utf8'))
        .trim()
        .split('\n')
        .map(JSON.parse);
      assert.deepEqual(records.map(e => e.occurrence_id).sort(), expected);
      assert.equal(
        exporter.delivery().counters['beacon.security.queued'],
        expected.length
      );
      assert.equal(exporter.delivery().dropped, 0);
    } finally {
      await exporter.close();
      clearInterval(keepAlive);
      delete process.env.BEACON_SECURITY_EVIDENCE_FILE;
      if (original === undefined) delete process.env[key];
      else process.env[key] = original;
      await rm(output, { recursive: true, force: true });
    }
  });
}

for (const [fragment, status] of [
  ['`unsupported`', 'unknown'],
  ['1 OR 1=1', 'suspected'],
]) {
  test(`filtered observations can upgrade to ${status} in the same request`, async () => {
    delete process.env[key];
    const keepAlive = setInterval(() => {}, 1000);
    const exporter = new Exporter(identity, 'upgrade');
    const logged = [];
    exporter.explicitLogger = {
      emit: record => logged.push(JSON.parse(record.body)),
    };
    const state = new SecurityState(identity);
    exporter.ledger.begin(state);
    try {
      const detect = value =>
        state.sink(
          'sql_injection',
          'template',
          'db.query',
          'app:query',
          state.source(value, 'http.request.parameter', 'id'),
          value
        );
      const first = detect('12');
      assert.equal(first.attack_evidence.status, 'no_evidence');
      assert.equal(exporter.emit(first), false);
      const upgrade = detect(fragment);
      assert.equal(upgrade.attack_evidence.status, status);
      assert.equal(upgrade.occurrence_id, first.occurrence_id);
      for (const event of exporter.ledger.end(state))
        assert.equal(exporter.emit(event), true);
      await exporter.close();
      assert.deepEqual(
        logged.map(event => event.attack_evidence.status),
        [status]
      );
    } finally {
      state.close();
      await exporter.close();
      clearInterval(keepAlive);
    }
  });
}
