import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { transform } from '../src/transform/index.mjs';
import * as values from '../src/core/values.mjs';
import * as operations from '../src/core/operations.mjs';
import * as calls from '../src/core/calls.mjs';

globalThis[Symbol.for('beacon.security.helpers.v1')] = Object.freeze({
  ...values,
  ...operations,
  ...calls,
});

const root = await mkdtemp(join(tmpdir(), 'security-node-transform-'));
const file = join(root, 'semantic.mjs');
const source = `
export function run(value) {
  const same = 'same-value-constant';
  let getterCalls = 0;
  const object = { get value() { getterCalls += 1; return value; } };
  const first = object.value;
  let assigned = 'before';
  assigned = first;
  const { value: destructured } = { value: assigned };
  function factorial(number) { return number <= 1 ? 1 : number * factorial(number - 1); }
  const shortCircuit = false && 'unreachable';
  return { same, first, assigned, destructured, getterCalls, recursive: factorial(5), shortCircuit };
}
`;
const transformed = transform(source, file, pathToFileURL(file).href);
assert.match(transformed.code, /beacon_security\.helpers\.v1/);
await writeFile(file, transformed.code, 'utf8');
const semantic = await import(`${pathToFileURL(file).href}?qa=semantic`);
assert.deepEqual(semantic.run('input-value'), {
  same: 'same-value-constant',
  first: 'input-value',
  assigned: 'input-value',
  destructured: 'input-value',
  getterCalls: 1,
  recursive: 120,
  shortCircuit: false,
});

const cycleA = join(root, 'cycle-a.mjs');
const cycleB = join(root, 'cycle-b.mjs');
const cycleSourceA = `import { bValue, readA } from './cycle-b.mjs'; export let aValue = 'a-initial'; export function update(value) { aValue = value; } export function read() { return { a: aValue, b: bValue, fromB: readA() }; }`;
const cycleSourceB = `import { aValue } from './cycle-a.mjs'; export const bValue = 'b-stable'; export function readA() { return aValue; }`;
await writeFile(
  cycleA,
  transform(cycleSourceA, cycleA, pathToFileURL(cycleA).href).code,
  'utf8'
);
await writeFile(
  cycleB,
  transform(cycleSourceB, cycleB, pathToFileURL(cycleB).href).code,
  'utf8'
);
// Keep the cycle's URL identical on both edges; a query intentionally creates
// a second ESM module instance and would test URL identity rather than live
// bindings.
const cycle = await import(pathToFileURL(cycleA).href);
assert.deepEqual(cycle.read(), {
  a: 'a-initial',
  b: 'b-stable',
  fromB: 'a-initial',
});
cycle.update('a-updated');
assert.deepEqual(cycle.read(), {
  a: 'a-updated',
  b: 'b-stable',
  fromB: 'a-updated',
});

process.stdout.write(
  `${JSON.stringify({ status: 'pass', node: process.version, transformedBytes: Buffer.byteLength(transformed.code), fixtureRoot: root })}\n`
);
