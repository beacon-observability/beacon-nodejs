import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { transform } from '../src/transform/index.mjs';
import * as values from '../src/core/values.mjs';
import * as calls from '../src/core/calls.mjs';
import * as operations from '../src/core/operations.mjs';
import { SecurityState } from '../src/core/state.mjs';
import { bind } from '../src/core/runtime.mjs';
import { installBuiltins, installLibrary } from '../src/adapters/sinks.mjs';

globalThis[Symbol.for('beacon.security.helpers.v1')] = {
  ...values,
  ...calls,
  ...operations,
};
installBuiltins();

test('transformed normalization, replacement callbacks, split and JSON preserve request provenance', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'beacon-string-models-'));
  const filename = join(directory, 'fixture.mjs');
  const source = `
    export function normalize(input, method) { return input.name[method](); }
    export function replace(input) { return input.name.replace(/A/g, 'B'); }
    export function replaceAll(input) { return input.name.replaceAll('A', '$&$&'); }
    export function callback(input) { return 'clean'.replace(/clean/, () => input.name); }
    export function callCallback(input) { return String.prototype.replace.call('clean', /clean/, () => input.name); }
    export function applyCallback(input) { return String.prototype.replace.apply('clean', [/clean/, () => input.name]); }
    export function boundCallback(input) { return String.prototype.replace.bind('clean', /clean/)(() => input.name); }
    export function padding(input) { return input.name.padStart(20, 'x').padEnd(25, 'y'); }
    export function split(input, separator) { return input.name.split(separator)[1]; }
    export function json(input) { return JSON.parse(JSON.stringify(input)).nested.name; }
    export function replacer(input) { return JSON.stringify({name:'clean'}, (key, value) => key === 'name' ? input.name : value); }
    export function reviver(input) { return JSON.parse('{"name":"clean"}', (key, value) => key === 'name' ? input.name : value).name; }
    export function sql(client, input) { return client.query('SELECT ' + input.name.trim()); }
  `;
  await writeFile(
    filename,
    transform(source, filename, pathToFileURL(filename).href).code
  );
  const fixture = await import(pathToFileURL(filename));
  class Client {
    query(value) {
      return value;
    }
  }
  installLibrary('pg', { Client });
  const run = (fn, input, extra = []) => {
    const state = new SecurityState({
      application_id: 'strings',
      instance_id: 'strings',
    });
    state.capture(input, 'http.request.body', 'body');
    try {
      return bind(state, () => {
        const result = calls.invoke(values.p(fn), [
          values.p(input),
          ...extra.map(values.p),
        ]);
        assert.ok(result.m.length, fn.name);
        assert.equal(state.gaps.has('unmodeled_call_result'), false, fn.name);
        return { value: result.v, marks: result.m };
      });
    } finally {
      state.close();
    }
  };
  try {
    for (const method of [
      'trim',
      'trimStart',
      'trimEnd',
      'trimLeft',
      'trimRight',
    ]) {
      const input = { name: ' \tAlice\u00a0' };
      const result = run(fixture.normalize, input, [method]);
      assert.equal(result.value, input.name[method]());
      assert.ok(result.marks.every(mark => mark.exact));
      assert.ok(
        result.marks.every(
          mark => mark.start >= 0 && mark.end <= result.value.length
        )
      );
    }
    for (const [method, name] of [
      ['toLowerCase', '\u0130USER'],
      ['toUpperCase', 'Straße'],
    ]) {
      const result = run(fixture.normalize, { name }, [method]);
      assert.equal(result.value, name[method]());
      assert.ok(result.marks.every(mark => !mark.exact));
    }
    assert.ok(
      run(fixture.normalize, { name: 'Alice' }, ['toLowerCase']).marks.every(
        mark => mark.exact
      )
    );
    for (const fn of [
      fixture.replace,
      fixture.replaceAll,
      fixture.callback,
      fixture.callCallback,
      fixture.applyCallback,
      fixture.boundCallback,
      fixture.padding,
    ])
      assert.equal(typeof run(fn, { name: 'Alice' }).value, 'string');
    const exactSplit = run(fixture.split, { name: 'first,Alice,last' }, [',']);
    assert.equal(exactSplit.value, 'Alice');
    assert.ok(exactSplit.marks.every(mark => mark.exact));
    const regexSplit = run(fixture.split, { name: 'first,Alice,last' }, [/,/]);
    assert.equal(regexSplit.value, 'Alice');
    assert.ok(regexSplit.marks.every(mark => !mark.exact));
    assert.equal(
      run(fixture.json, { nested: { name: 'Alice' } }).value,
      'Alice'
    );
    assert.equal(
      run(fixture.replacer, { name: 'Alice' }).value,
      '{"name":"Alice"}'
    );
    assert.equal(run(fixture.reviver, { name: 'Alice' }).value, 'Alice');
    const state = new SecurityState({
      application_id: 'strings',
      instance_id: 'strings',
    });
    const input = { name: ' Alice ' };
    state.capture(input, 'http.request.parameter', 'query');
    bind(state, () => fixture.sql(new Client(), input));
    assert.equal(state.pending.length, 1);
    assert.equal(state.pending[0].rule, 'sql_injection');
    state.close();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('replacement models do not repeat callback or coercion side effects', () => {
  const state = new SecurityState({
    application_id: 'strings',
    instance_id: 'strings',
  });
  let callbacks = 0,
    conversions = 0;
  const input = 'AA';
  const replacement = {
    toString() {
      conversions++;
      return 'B';
    },
  };
  try {
    bind(state, () => {
      const receiver = values.p(
        input,
        state.source(input, 'http.request.parameter', 'q')
      );
      const result = calls.invoke(
        { v: String.prototype.replaceAll, receiver },
        [values.p('A'), values.p(replacement)]
      );
      assert.equal(result.v, 'BB');
      assert.equal(conversions, 1);
      const replaced = calls.invoke(
        { v: String.prototype.replaceAll, receiver },
        [
          values.p('A'),
          values.p(() => {
            callbacks++;
            return 'B';
          }),
        ]
      );
      assert.equal(replaced.v, 'BB');
      assert.equal(callbacks, 2);
      const clean = calls.invoke(
        { v: String.prototype.toLowerCase, receiver: values.p('CONSTANT') },
        [receiver]
      );
      assert.equal(
        clean.m.length,
        0,
        'ignored case-conversion arguments must not become sources'
      );
      assert.throws(
        () =>
          calls.invoke({ v: String.prototype.replaceAll, receiver }, [
            values.p(/A/),
            values.p('B'),
          ]),
        TypeError
      );
    });
  } finally {
    state.close();
  }
});
