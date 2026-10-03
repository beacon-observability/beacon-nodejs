import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { transform } from '../src/transform/index.mjs';
import * as values from '../src/core/values.mjs';
import * as operations from '../src/core/operations.mjs';
import * as calls from '../src/core/calls.mjs';
import { SecurityState } from '../src/core/state.mjs';
import { bind } from '../src/core/runtime.mjs';
import { installBuiltins } from '../src/adapters/sinks.mjs';

const helperKey = Symbol.for('beacon.security.helpers.v1');
globalThis[helperKey] = Object.freeze({ ...values, ...operations, ...calls });
installBuiltins();

const ESM_SOURCE = `
import { readFile } from 'node:fs/promises';

export async function run(input) {
  const tainted = input.path;
  const constructed = await new Promise((resolve) => resolve(tainted));
  const resolved = await Promise.resolve(constructed);
  const chained = await Promise.resolve(tainted).then((value) => value);
  const all = await Promise.all([constructed, resolved, chained]);
  function combine(prefix, value) { return prefix + ':' + value; }
  const called = combine.call(null, 'call', tainted);
  const applied = combine.apply(null, ['apply', tainted]);
  const bound = combine.bind(null, 'bind');
  const boundValue = bound(tainted);
  let getterReads = 0;
  const wrapped = { get value() { getterReads += 1; return tainted; } };
  const getter = wrapped.value;
  const closure = (() => tainted)();
  const concurrent = await Promise.all([
    Promise.resolve(tainted),
    new Promise((resolve) => queueMicrotask(() => resolve(tainted))),
  ]);
  const fsContent = await readFile(tainted, 'utf8');
  return { constructed, resolved, chained, all, called, applied, boundValue, getter, closure, concurrent, getterReads, fsContent };
}
`;

const CJS_SOURCE = `
const { readFile } = require('node:fs/promises');

async function run(input) {
  const tainted = input.path;
  const constructed = await new Promise((resolve) => resolve(tainted));
  const resolved = await Promise.resolve(constructed);
  const chained = await Promise.resolve(tainted).then((value) => value);
  const all = await Promise.all([constructed, resolved, chained]);
  function combine(prefix, value) { return prefix + ':' + value; }
  const called = combine.call(null, 'call', tainted);
  const applied = combine.apply(null, ['apply', tainted]);
  const bound = combine.bind(null, 'bind');
  const boundValue = bound(tainted);
  let getterReads = 0;
  const wrapped = { get value() { getterReads += 1; return tainted; } };
  const getter = wrapped.value;
  const closure = (() => tainted)();
  const concurrent = await Promise.all([
    Promise.resolve(tainted),
    new Promise((resolve) => queueMicrotask(() => resolve(tainted))),
  ]);
  const fsContent = await readFile(tainted, 'utf8');
  return { constructed, resolved, chained, all, called, applied, boundValue, getter, closure, concurrent, getterReads, fsContent };
}

module.exports = { run };
`;

const identity = variant => ({
  application_id: 'security-qa-taint',
  instance_id: `taint-${variant}`,
  service: {},
});

async function loadVariant(root, variant) {
  const extension = variant === 'esm' ? 'mjs' : 'cjs';
  const file = join(root, `taint-${variant}.${extension}`);
  const source = variant === 'esm' ? ESM_SOURCE : CJS_SOURCE;
  const transformed = transform(source, file, pathToFileURL(file).href);
  await writeFile(file, transformed.code, 'utf8');
  const module =
    variant === 'esm'
      ? await import(pathToFileURL(file).href)
      : createRequire(import.meta.url)(file);
  return { file, module };
}

async function execute(state, module, input) {
  state.capture(input, 'http.request.path', 'flow.path', 'taint-smoke#capture');
  return bind(state, () => module.run(input));
}

function assertTainted(state, value, label) {
  const marks = state.field(value, label);
  assert.ok(marks.length > 0, `${label} must retain taint marks`);
  assert.ok(
    marks.every(mark => mark.state === state.id),
    `${label} leaked a cross-request mark`
  );
}

function assertRecord(record, target) {
  const { state, result } = record;
  assert.equal(result.fsContent, 'taint-fixture\n');
  assert.equal(result.getterReads, 1);
  for (const key of [
    'constructed',
    'resolved',
    'chained',
    'called',
    'applied',
    'boundValue',
    'getter',
    'closure',
  ]) {
    assertTainted(state, result, key);
  }
  for (const key of ['0', '1', '2']) assertTainted(state, result.all, key);
  for (const key of ['0', '1']) assertTainted(state, result.concurrent, key);
  assert.equal(
    state.pending.filter(
      event =>
        event.rule === 'path_traversal' && event.sink.function === 'fs.readFile'
    ).length,
    1
  );
  assert.equal(state.sources.size, 1);
  assert.equal([...state.sources.values()][0].name, 'flow.path.path');
  assert.equal(target, result.constructed);
}

async function runVariant(root, variant, target) {
  const { module } = await loadVariant(root, variant);
  const state = new SecurityState(identity(variant), {
    method: 'GET',
    url: `/taint/${variant}`,
  });
  const input = { path: target };
  const result = await execute(state, module, input);
  return { state, result };
}

const root = await mkdtemp(join(tmpdir(), 'security-node-taint-'));
try {
  const target = join(root, 'source.txt');
  await writeFile(target, 'taint-fixture\n', 'utf8');
  const records = await Promise.all([
    runVariant(root, 'esm', target),
    runVariant(root, 'cjs', target),
  ]);
  for (const [index, record] of records.entries()) {
    assertRecord(record, target);
    assert.ok(
      record.state.pending[0].sources.some(
        source => source.name === 'flow.path.path'
      ),
      `variant ${index} source missing from fs sink`
    );
  }

  // Run two transformed modules concurrently with distinct states.  Every
  // output field must keep its own source id while both Promise branches are
  // in flight; a value-only assertion would miss cross-request contamination.
  const { module: esm } = await loadVariant(root, 'esm');
  const left = new SecurityState(identity('left'), {
    method: 'GET',
    url: '/taint/left',
  });
  const right = new SecurityState(identity('right'), {
    method: 'GET',
    url: '/taint/right',
  });
  const leftInput = { path: target };
  const rightInput = { path: target };
  left.capture(leftInput, 'http.request.path', 'flow.left', 'taint-smoke#left');
  right.capture(
    rightInput,
    'http.request.path',
    'flow.right',
    'taint-smoke#right'
  );
  const [leftResult, rightResult] = await Promise.all([
    bind(left, () => esm.run(leftInput)),
    bind(right, () => esm.run(rightInput)),
  ]);
  assertTainted(left, leftResult, 'called');
  assertTainted(right, rightResult, 'called');
  assert.equal(left.field(leftResult, 'called')[0].state, left.id);
  assert.equal(right.field(rightResult, 'called')[0].state, right.id);
  assert.equal(left.pending.length, 1);
  assert.equal(right.pending.length, 1);
  left.close();
  right.close();
  for (const record of records) record.state.close();
  process.stdout.write(
    `${JSON.stringify({
      status: 'pass',
      node: process.version,
      variants: ['esm', 'cjs'],
      assertions: [
        'capture',
        'promise-constructor',
        'promise-resolve',
        'promise-then',
        'promise-all',
        'call',
        'apply',
        'bind',
        'getter-once',
        'closure',
        'concurrent-isolation',
        'fs-sink',
      ],
      fixtureRoot: root,
    })}\n`
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
