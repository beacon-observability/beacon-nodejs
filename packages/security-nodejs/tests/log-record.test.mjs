import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';
import { logRecord, eventTime } from '../src/log-record.mjs';
import { Exporter } from '../src/exporter/index.mjs';
const root = new URL('./fixtures/spec/current/examples/', import.meta.url);
for (const name of await readdir(new URL('log-records/', root))) {
  test(`shared log binding: ${name}`, async () => {
    const inputName =
      name === 'finding.json'
        ? 'finding-v2.json'
        : name === 'finding-occurrence.json'
          ? 'finding-occurrence-v2.json'
          : name === 'sbom-inventory.json'
            ? 'sbom-inventory-v2.json'
            : `siem/inputs/${name}`;
    const input = JSON.parse(await readFile(new URL(inputName, root), 'utf8'));
    const expected = JSON.parse(
      await readFile(new URL(`log-records/${name}`, root), 'utf8')
    );
    assert.deepEqual(logRecord(input), expected);
    assert.deepEqual(logRecord(input), logRecord(input));
    const exporter = new Exporter();
    const records = [];
    exporter.explicitLogger = { emit: record => records.push(record) };
    try {
      await exporter._emitOtel(expected.body, input);
      const record = records[0];
      assert.equal(
        String(
          BigInt(record.timestamp[0]) * 1000000000n +
            BigInt(record.timestamp[1])
        ),
        expected.time_unix_nano
      );
      assert.equal(record.body, expected.body);
      assert.equal(record.attributes.event_id, expected.attributes.event_id);
    } finally {
      await exporter.close();
    }
  });
}
test('integer timestamp precision, invalid times and escaped Unicode', () => {
  assert.equal(
    eventTime('2026-10-02T00:00:00.123456789Z'),
    1790899200123456789n
  );
  for (const value of [
    'bad',
    '2026-02-30T00:00:00Z',
    '2026-02-30T00:00:00+08:00',
    '1970-01-01T00:00:00Z',
    '1969-12-31T23:59:59Z',
    '2263-01-01T00:00:00Z',
  ])
    assert.throws(() => eventTime(value));
  const input = {
    schema_version: 2,
    event_name: 'beacon.security.finding',
    source: 'beacon_security',
    observed_at: '2026-10-02T00:00:00Z',
    occurrence_id: 'one',
    stack: ['中文\\路径"\n😀'],
  };
  assert.deepEqual(JSON.parse(logRecord(input).body).stack, input.stack);
  assert.ok(!/[\r\n]/.test(logRecord(input).body));
  assert.ok(!('observed_at' in JSON.parse(logRecord(input).body)));
});
