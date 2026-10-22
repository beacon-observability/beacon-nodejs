import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze } from '../src/core/attack-evidence.mjs';

const mark = (text, input) => ({
  start: text.indexOf(input),
  end: text.indexOf(input) + input.length,
  exact: true,
  unit: 'utf16_code_unit',
});

test('ANSI literal contents do not suppress later structural evidence', () => {
  process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
  for (const literal of ['$100', '[a-z]%', '\\[a\\]%', '`value`']) {
    const text = `SELECT '${literal}' FROM users WHERE id=1 OR 1=1`;
    assert.equal(
      analyze('sql_injection', 'sql_template', text, [mark(text, '1 OR 1=1')])
        .status,
      'suspected'
    );
  }
  const unsupported = 'SELECT $1 FROM users WHERE id=1 OR 1=1';
  assert.equal(
    analyze('sql_injection', 'sql_template', unsupported, [
      mark(unsupported, '1 OR 1=1'),
    ]).status,
    'unknown'
  );
});

test('tainted quotes that cross a trusted literal boundary are structural evidence', () => {
  const text = "ls '' -la /etc ''";
  const result = analyze(
    'command_injection',
    'shell_script',
    text,
    [mark(text, "' -la /etc '")],
    'sh'
  );
  assert.equal(result.status, 'suspected');
  assert.equal(result.outcome, 'not_assessed');
  for (const [value, input] of [
    ["echo 'a;b'", 'a;b'],
    ["echo 'a;b'", "'a;b'"],
    ["echo 'O''Reilly'", 'O'],
  ]) {
    assert.equal(
      analyze(
        'command_injection',
        'shell_script',
        value,
        [mark(value, input)],
        'sh'
      ).status,
      'no_evidence'
    );
  }
  const incomplete = "echo 'unclosed";
  assert.equal(
    analyze(
      'command_injection',
      'shell_script',
      incomplete,
      [mark(incomplete, 'unclosed')],
      'sh'
    ).status,
    'unknown'
  );
});

test('SQL whitespace analysis has a linear deterministic operation bound', t => {
  process.env.BEACON_SECURITY_ANALYSIS_SQL_DIALECT = 'ansi';
  const original = RegExp.prototype.test;
  let whitespaceTests = 0;
  t.mock.method(RegExp.prototype, 'test', function (value) {
    if (this.source === '\\s') whitespaceTests++;
    return Reflect.apply(original, this, [value]);
  });
  for (const length of [1024, 2048, 4096, 8000]) {
    const text = 'SELECT 1' + ' '.repeat(length);
    whitespaceTests = 0;
    const result = analyze('sql_injection', 'sql_template', text, [
      { ...mark(text, '1'), end: text.length },
    ]);
    assert.equal(result.status, 'no_evidence');
    assert.ok(
      whitespaceTests <= text.length * 4,
      `${length}: ${whitespaceTests}`
    );
  }
});
