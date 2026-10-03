import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';

import { transform } from '../src/transform/index.mjs';
import * as values from '../src/core/values.mjs';
import * as operations from '../src/core/operations.mjs';
import * as calls from '../src/core/calls.mjs';
import { SecurityState } from '../src/core/state.mjs';
import { bind } from '../src/core/runtime.mjs';
import { installBuiltins } from '../src/adapters/models.mjs';

globalThis[Symbol.for('beacon.security.helpers.v1')] = Object.freeze({
  ...values,
  ...operations,
  ...calls,
});

test('unsupported object boundaries preserve business values and exceptions', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-object-boundaries-'));
  const state = new SecurityState(identity('object-boundaries'));
  try {
    const { module: fixture } = await loadTransformed(
      root,
      'objects',
      `
      function identity(value) { return value; }
      export function returned(value) { return identity(value); }
      export function accessed(value) { const box = { get value() { return value; } }; return box.value; }
      export function shorthand(value) { const __proto__ = value; return { __proto__ }; }
      export function prototype(value) { return { __proto__: value }; }
      class Box { #value = 42; #read() { return this.#value; } read(other) { return other?.#value; } call(other) { return other?.#read(); } }
      export function privateValue(kind) { const box = new Box(); return [box.read(kind ? {} : box), box.read(null), box.call(box)]; }
    `
    );
    const proxy = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('business prototype probe');
        },
      }
    );
    const value = { marker: 1 };
    for (const active of [false, true]) {
      const run = fn => (active ? bind(state, fn) : fn());
      assert.equal(
        run(() => fixture.returned(proxy)),
        proxy
      );
      assert.equal(
        run(() => fixture.accessed(proxy)),
        proxy
      );
      const result = run(() => fixture.shorthand(value));
      assert.equal(Object.getPrototypeOf(result), Object.prototype);
      assert.equal(
        Object.getOwnPropertyDescriptor(result, '__proto__').value,
        value
      );
      assert.equal(
        Object.getPrototypeOf(run(() => fixture.prototype(value))),
        value
      );
      assert.deepEqual(
        run(() => fixture.privateValue(false)),
        [42, undefined, 42]
      );
      assert.throws(() => run(() => fixture.privateValue(true)), TypeError);
    }
  } finally {
    state.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('numeric loop optimization preserves tainted inputs when their type is unknown', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-numeric-boundaries-'));
  const state = new SecurityState(identity('numeric-boundaries'));
  try {
    const { module: fixture } = await loadTransformed(
      root,
      'numbers',
      `
      export function numeric(n, input) { let total = 0; for (let i=0; i<n; i++) total += i % 17; return input.value + total; }
      export function dynamic(input) { let total = 0; for (let i=0; i<3; i++) total += input.value; return total; }
      export function evaluated() { let total=0; eval('total="x"'); for(let i=0;i<3;i++) total+=i; return total; }
    `
    );
    const input = { value: 'request-value' };
    state.capture(input, 'http.request.parameter', 'query');
    bind(state, () => {
      const normal = calls.invoke(values.p(fixture.numeric), [
        values.p(100),
        values.p(input),
      ]);
      assert.equal(normal.v, 'request-value785');
      assert.ok(normal.m.length);
      const dynamic = calls.invoke(values.p(fixture.dynamic), [
        values.p(input),
      ]);
      assert.equal(dynamic.v, '0request-valuerequest-valuerequest-value');
      assert.ok(dynamic.m.length);
      assert.equal(fixture.evaluated(), 'x012');
    });
  } finally {
    state.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('reverse numeric dependencies retain taint after invalidation through chains and cycles', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-numeric-chain-'));
  const state = new SecurityState(identity('numeric-chain'));
  try {
    const count = 256;
    const declarations = Array.from(
      { length: count },
      (_, i) => `let value${i} = 0;`
    ).join('\n');
    const writes = Array.from(
      { length: count - 1 },
      (_, i) => `value${count - i - 2} = value${count - i - 1};`
    ).join('\n');
    const { module: fixture } = await loadTransformed(
      root,
      'chain',
      `
      export function chain(input) { ${declarations} value${count - 1} = input.value; ${writes} return value0; }
      export function cycle(input) { let a=0, b=0; a=b; b=a; b=input.value; a=b; return a; }
    `
    );
    const input = { value: 'tainted-chain' };
    state.capture(input, 'http.request.parameter', 'query');
    bind(state, () => {
      for (const fn of [fixture.chain, fixture.cycle]) {
        const result = calls.invoke(values.p(fn), [values.p(input)]);
        assert.equal(result.v, input.value);
        assert.ok(
          result.m.length && result.m.every(mark => mark.state === state.id)
        );
      }
    });
  } finally {
    state.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('shared Promise results finish without expanding a DAG and wide metadata degrades safely', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-promise-dag-'));
  try {
    await writeFile(
      join(root, 'promises.mjs'),
      `
      export async function dag(input) {
        let pending = Promise.resolve(input.value);
        for (let i=0; i<28; i++) pending=Promise.all([pending,pending]);
        return await pending;
      }
      export async function wide() {
        const groups=[];
        for(let i=0;i<100;i++) {
          const items=[];
          for(let j=0;j<100;j++) items.push(Promise.resolve(i*100+j));
          groups.push(Promise.all(items));
        }
        return await Promise.all(groups);
      }
      export async function settled(input, error) {
        const pending=Promise.resolve(input.value);
        return await Promise.allSettled([pending,pending,Promise.reject(error)]);
      }
      export function create(input) { return Promise.all([Promise.resolve(input.value)]); }
    `
    );
    const source = `
      import assert from 'node:assert/strict';
      import * as calls from ${JSON.stringify(new URL('../src/core/calls.mjs', import.meta.url).href)};
      import * as values from ${JSON.stringify(new URL('../src/core/values.mjs', import.meta.url).href)};
      import {SecurityState} from ${JSON.stringify(new URL('../src/core/state.mjs', import.meta.url).href)};
      import {bind,shutdown} from ${JSON.stringify(new URL('../src/core/runtime.mjs', import.meta.url).href)};
      const fixture=await import(${JSON.stringify(pathToFileURL(join(root, 'promises.mjs')).href)});
      for(const marked of [true,false]) {
        const state=new SecurityState({}), input={value:'shared-leaf'};
        if(marked) state.capture(input,'http.request.parameter','query');
        try {
          let result=await bind(state,()=>fixture.dag(input));
          for(let i=0;i<28;i++) {
            assert.equal(result[0],result[1]);
            if(i===27) assert.equal(state.field(result,'0').length>0,marked);
            result=result[0];
          }
          assert.equal(result,input.value);
          assert.equal(state.gaps.has('promise_metadata_work_limit'),false);
          const error=new Error('expected-rejection');
          const settled=await bind(state,()=>fixture.settled(input,error));
          assert.equal(settled[0].value,input.value);
          assert.equal(state.field(settled[0],'value').length>0,marked);
          assert.equal(settled[2].reason,error);
          const pending=bind(state,()=>fixture.create(input)), mutated=await pending;
          let reads=0;
          Object.defineProperty(mutated,'0',{get(){reads++;throw new Error('business getter');}});
          assert.equal(bind(state,()=>calls.awaited(values.p(pending),mutated)).v,mutated);
          assert.equal(reads,0);
          assert.equal(state.gaps.has('promise_result_mutated'),true);
          const wide=await bind(state,()=>fixture.wide());
          assert.equal(wide.length,100); assert.equal(wide[99][99],9999);
          assert.equal(state.gaps.has('promise_metadata_work_limit'),true);
        } finally {state.close();}
      }
      await shutdown();
    `;
    execFileSync(
      process.execPath,
      [
        '--import',
        new URL('../src/register.mjs', import.meta.url).href,
        '--input-type=module',
        '--eval',
        source,
      ],
      {
        timeout: 10000,
        env: {
          ...process.env,
          BEACON_SECURITY_ENABLED: 'true',
          BEACON_SECURITY_SBOM_ENABLED: 'false',
          BEACON_SECURITY_NODE_INCLUDE: root,
          BEACON_SECURITY_OUTPUT: join(root, 'output'),
        },
      }
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('cyclic star and named re-exports preserve live bindings without blocking or sharing request marks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-export-cycles-'));
  try {
    const files = {
      'leaf.mjs': `export let value = 'clean'; export function set(next) { value = next; }`,
      'a.mjs': `export * from './b.mjs'; export * from './c.mjs'; export * from './leaf.mjs';`,
      'b.mjs': `export * from './a.mjs'; export * from './c.mjs'; export * from './leaf.mjs';`,
      'c.mjs': `export * from './a.mjs'; export * from './b.mjs'; export * from './leaf.mjs';`,
      'alias.mjs': `export {value as renamed, set} from './a.mjs';`,
      'entry.mjs': `import {renamed, set} from './alias.mjs';
        export function read() { return renamed; }
        export function write(input) { set(input.value); return renamed; }
        export function clear() { set('clean'); return renamed; }`,
    };
    for (const [name, source] of Object.entries(files))
      await writeFile(join(root, name), source);
    const source = `
      import assert from 'node:assert/strict';
      import * as calls from ${JSON.stringify(new URL('../src/core/calls.mjs', import.meta.url).href)};
      import * as values from ${JSON.stringify(new URL('../src/core/values.mjs', import.meta.url).href)};
      import {SecurityState} from ${JSON.stringify(new URL('../src/core/state.mjs', import.meta.url).href)};
      import {bind, shutdown} from ${JSON.stringify(new URL('../src/core/runtime.mjs', import.meta.url).href)};
      const fixture = await import(${JSON.stringify(pathToFileURL(join(root, 'entry.mjs')).href)});
      assert.equal(fixture.read(), 'clean');
      const left = new SecurityState({}), right = new SecurityState({});
      const read = state => bind(state, () => calls.invoke(values.p(fixture.read), []));
      try {
        assert.equal(read(left).m.length, 0);
        for (const state of [left, right]) {
          assert.equal(read(state).m.length, 0);
          const input = {value: 'request-' + state.id};
          state.capture(input, 'http.request.parameter', 'query');
          const written = bind(state, () => calls.invoke(values.p(fixture.write), [values.p(input)]));
          assert.equal(written.v, input.value);
          assert.ok(written.m.length && written.m.every(mark => mark.state === state.id));
          assert.deepEqual(read(state).m, written.m);
        }
        assert.equal(read(left).m.length, 0);
        assert.equal(bind(right, () => calls.invoke(values.p(fixture.clear), [])).m.length, 0);
        assert.equal(read(right).v, 'clean');
        assert.equal(read(right).m.length, 0);
        assert.equal(right.gaps.has('export_metadata_limit'), false);
      } finally { left.close(); right.close(); await shutdown(); }
    `;
    execFileSync(
      process.execPath,
      [
        '--import',
        new URL('../src/register.mjs', import.meta.url).href,
        '--input-type=module',
        '--eval',
        source,
      ],
      {
        timeout: 10000,
        env: {
          ...process.env,
          BEACON_SECURITY_ENABLED: 'true',
          BEACON_SECURITY_SBOM_ENABLED: 'false',
          BEACON_SECURITY_NODE_INCLUDE: root,
          BEACON_SECURITY_OUTPUT: join(root, 'output'),
        },
      }
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('wide export lookup degrades within its work budget and the next query can still propagate', () => {
  const state = new SecurityState(identity('export-budget'));
  const parent = 'export-budget-' + state.id,
    root = parent + '/root';
  calls.resolveModule(parent, './root', root);
  for (let index = 0; index < 300; index++) {
    calls.exportAll(root, './' + index);
    calls.resolveModule(root, './' + index, root + '/' + index);
  }
  const leaf = root + '/299';
  let marks = state.source('request-value', 'http.request.parameter', 'query');
  calls.exportMarks(leaf, 'value', () => marks);
  try {
    bind(state, () => {
      assert.deepEqual(calls.importMarks(parent, './root', 'value'), []);
      assert.ok(state.gaps.has('export_metadata_limit'));
      assert.deepEqual(calls.importMarks(root, './299', 'value'), marks);
      marks = [];
      assert.deepEqual(calls.importMarks(root, './299', 'value'), []);
    });
  } finally {
    state.close();
  }
});

test('large modules finish conversion without colliding with business bindings', () => {
  const source = `
    import assert from 'node:assert/strict';
    import {transform} from ${JSON.stringify(new URL('../src/transform/index.mjs', import.meta.url).href)};
    import * as calls from ${JSON.stringify(new URL('../src/core/calls.mjs', import.meta.url).href)};
    import * as values from ${JSON.stringify(new URL('../src/core/values.mjs', import.meta.url).href)};
    import * as operations from ${JSON.stringify(new URL('../src/core/operations.mjs', import.meta.url).href)};
    globalThis[Symbol.for('beacon.security.helpers.v1')] = {...calls, ...values, ...operations};
    {
      const count = 8000;
      const source = Array.from({length: count}, (_, i) => 'const value' + i + ' = ' + (i === 0 ? '"clean"' : i) + ';').join('\\n') +
        '\\nconst _security1value0Marks = "occupied"; module.exports = [value' + (count - 1) + ', value0, _security1value0Marks];';
      const result = transform(source, '/tmp/large-module.cjs', undefined, undefined, 'commonjs');
      const module = {exports: null};
      new Function('module', result.code)(module);
      assert.deepEqual(module.exports, [count - 1, 'clean', 'occupied']);
      assert.equal(result.gaps?.length || 0, 0);
    }
  `;
  execFileSync(process.execPath, ['--input-type=module', '--eval', source], {
    timeout: 10000,
  });
});

const identity = variant => ({
  application_id: 'security-core-semantics',
  instance_id: `core-semantics-${variant}`,
  service: {},
  code: {},
  runtime: {},
  identity_status: 'configured',
});

const ESM_SOURCE = `
export async function exercise(input) {
  const captured = input.value;
  const closure = () => captured;
  function recurse(depth) { return depth === 0 ? captured : recurse(depth - 1); }
  await new Promise((resolve) => queueMicrotask(resolve));
  const recursive = recurse(4);
  const closed = closure();

  const same = 'same-value';
  let overwritten = captured;
  overwritten = 'same-value';
  const preserved = captured;
  const { value: provided = 'default-value' } = input;
  const { missing = 'default-value' } = input;

  const globalThis = captured;
  const Symbol = 'local-symbol';
  const undefined = 'local-undefined';
  const reserved = { globalThis, Symbol, undefined };

  let getterReads = 0;
  let setterWrites = 0;
  let assigned;
  const box = {
    get value() { getterReads += 1; return input.number; },
    set value(next) { setterWrites += 1; assigned = next; },
  };
  const incrementBefore = box.value++;
  const incrementAssigned = assigned;

  const concurrent = await Promise.all([
    new Promise((resolve) => queueMicrotask(() => resolve(input.left))),
    new Promise((resolve) => setImmediate(() => resolve(input.right))),
  ]);

  let fallbackEvaluations = 0;
  function fallback(value = (fallbackEvaluations += 1, 'fallback-value')) { return { value, fallbackEvaluations }; }
  const fallbackResult = fallback();

  let exceptionCalls = 0;
  let exceptionMessage = '';
  function throwsOnce() {
    exceptionCalls += 1;
    throw new Error('semantic-once');
  }
  try { throwsOnce(); } catch (error) { exceptionMessage = error.message; }

  return {
    recursive, closed, same, overwritten, preserved, provided, missing,
    reserved, incrementBefore, incrementAssigned, getterReads, setterWrites,
    concurrent, fallbackResult, exceptionCalls, exceptionMessage,
  };
}
`;

const STRICT_NO_EXPORT_SOURCE = `
function strictExercise(input) {
  const thisUndefined = this === undefined;
  let assignmentError = false;
  try { accidentalSecurityBinding = input.value; } catch (error) {
    assignmentError = error instanceof ReferenceError;
  }
  return { thisUndefined, assignmentError };
}
globalThis.__securityCoreStrictExercise = strictExercise;
`;

const CJS_SLOPPY_SOURCE = `
function sloppy(value) {
  const before = value;
  arguments[0] = 'constant';
  const after = value;
  return { before, after };
}
module.exports = { sloppy };
`;

async function loadTransformed(root, name, source, extension = 'mjs', format) {
  const file = join(root, `${name}.${extension}`);
  const url = pathToFileURL(file).href;
  const transformed = transform(source, file, url, undefined, format);
  await writeFile(file, transformed.code, 'utf8');
  const module =
    extension === 'cjs'
      ? createRequire(import.meta.url)(file)
      : await import(`${url}?core-semantics=${name}`);
  return { file, module, transformed };
}

function seed(state, input, name) {
  state.capture(input, 'http.request.body', name, `core-semantics#${name}`);
}

function fieldMarks(state, value, key, label) {
  const marks = state.field(value, key);
  assert.ok(marks.length > 0, `${label} should retain marks`);
  assert.ok(
    marks.every(mark => mark.state === state.id),
    `${label} leaked a cross-request mark`
  );
  return marks;
}

function cleanField(state, value, key, label) {
  assert.equal(state.field(value, key).length, 0, `${label} should be clean`);
}

function sourceNames(state) {
  return [...state.sources.values()].map(source => source.name);
}

test(
  'transformed state keeps request-local semantics across hard boundaries',
  { concurrency: false },
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'security-node-core-semantics-'));
    const strictKey = '__securityCoreStrictExercise';
    try {
      const { module: esm } = await loadTransformed(
        root,
        'exercise',
        ESM_SOURCE
      );
      const { module: strictModule } = await loadTransformed(
        root,
        'strict-no-export',
        STRICT_NO_EXPORT_SOURCE,
        'mjs',
        'module'
      );
      const { module: cjs } = await loadTransformed(
        root,
        'sloppy',
        CJS_SLOPPY_SOURCE,
        'cjs',
        'commonjs'
      );

      const left = new SecurityState(identity('left'), {
        method: 'POST',
        url: '/semantics/left',
      });
      const right = new SecurityState(identity('right'), {
        method: 'POST',
        url: '/semantics/right',
      });
      const leftInput = {
        value: 'same-value',
        number: 7,
        left: 'left-value',
        right: 'left-right',
      };
      const rightInput = {
        value: 'same-value',
        number: 8,
        left: 'right-value',
        right: 'right-right',
      };
      seed(left, leftInput, 'left.input');
      seed(right, rightInput, 'right.input');

      const [leftResult, rightResult] = await Promise.all([
        bind(left, () => esm.exercise(leftInput)),
        bind(right, () => esm.exercise(rightInput)),
      ]);

      for (const [state, input, result, prefix] of [
        [left, leftInput, leftResult, 'left'],
        [right, rightInput, rightResult, 'right'],
      ]) {
        assert.equal(result.recursive, input.value);
        assert.equal(result.closed, input.value);
        assert.equal(result.same, 'same-value');
        assert.equal(result.overwritten, 'same-value');
        assert.equal(result.preserved, input.value);
        assert.equal(result.provided, input.value);
        assert.equal(result.missing, 'default-value');
        assert.deepEqual(result.reserved, {
          globalThis: input.value,
          Symbol: 'local-symbol',
          undefined: 'local-undefined',
        });
        assert.equal(result.incrementBefore, input.number);
        assert.equal(result.incrementAssigned, input.number + 1);
        assert.equal(result.getterReads, 1);
        assert.equal(result.setterWrites, 1);
        assert.deepEqual(result.concurrent, [input.left, input.right]);
        assert.deepEqual(result.fallbackResult, {
          value: 'fallback-value',
          fallbackEvaluations: 1,
        });
        assert.equal(state.gaps.has('default_expression_propagation'), true);
        cleanField(
          state,
          result.fallbackResult,
          'value',
          `${prefix}.fallbackResult.value`
        );
        assert.equal(result.exceptionCalls, 1);
        assert.equal(result.exceptionMessage, 'semantic-once');

        fieldMarks(state, result, 'recursive', `${prefix}.recursive`);
        fieldMarks(state, result, 'closed', `${prefix}.closed`);
        fieldMarks(state, result, 'preserved', `${prefix}.preserved`);
        fieldMarks(state, result, 'provided', `${prefix}.provided`);
        cleanField(state, result, 'same', `${prefix}.same`);
        cleanField(state, result, 'overwritten', `${prefix}.overwritten`);
        cleanField(state, result, 'missing', `${prefix}.missing`);
        fieldMarks(
          state,
          result.reserved,
          'globalThis',
          `${prefix}.reserved.globalThis`
        );
        cleanField(
          state,
          result.reserved,
          'Symbol',
          `${prefix}.reserved.Symbol`
        );
        cleanField(
          state,
          result.reserved,
          'undefined',
          `${prefix}.reserved.undefined`
        );
        fieldMarks(
          state,
          result,
          'incrementBefore',
          `${prefix}.incrementBefore`
        );
        fieldMarks(
          state,
          result,
          'incrementAssigned',
          `${prefix}.incrementAssigned`
        );
        fieldMarks(state, result.concurrent, '0', `${prefix}.concurrent[0]`);
        fieldMarks(state, result.concurrent, '1', `${prefix}.concurrent[1]`);

        const names = sourceNames(state);
        for (const suffix of ['value', 'number', 'left', 'right']) {
          assert.ok(
            names.some(name => name === `${prefix}.input.${suffix}`),
            `${prefix} source ${suffix} missing`
          );
        }
        assert.ok(
          fieldMarks(state, result, 'recursive', `${prefix}.recursive`).every(
            mark =>
              state.sources.get(mark.source_id)?.name ===
              `${prefix}.input.value`
          )
        );
      }

      const leftRecursive = fieldMarks(
        left,
        leftResult,
        'recursive',
        'left recursive'
      )[0];
      const rightRecursive = fieldMarks(
        right,
        rightResult,
        'recursive',
        'right recursive'
      )[0];
      assert.notEqual(
        leftRecursive.state,
        rightRecursive.state,
        'same text in concurrent requests must keep distinct request marks'
      );
      assert.notEqual(
        left.sources.get(leftRecursive.source_id)?.name,
        right.sources.get(rightRecursive.source_id)?.name,
        'same text in concurrent requests must keep distinct source names'
      );

      const strictFn = globalThis[strictKey];
      const strictResult = await bind(left, () => strictFn(leftInput));
      assert.equal(
        strictResult.thisUndefined,
        true,
        'ESM without import/export must retain strict this semantics'
      );
      assert.equal(
        strictResult.assignmentError,
        true,
        'ESM implicit assignment must remain a ReferenceError'
      );
      assert.deepEqual(
        Object.keys(strictModule),
        [],
        'strict fixture intentionally has no static exports'
      );

      const sloppyInput = { value: 'same-value' };
      seed(left, sloppyInput, 'left.sloppy');
      const argumentMarks = left.field(sloppyInput, 'value');
      const sloppyResult = await bind(
        left,
        () =>
          calls.invoke(
            { v: cjs.sloppy, receiver: values.p(undefined) },
            [values.p(sloppyInput.value, argumentMarks)],
            'core-semantics#sloppy'
          ).v
      );
      assert.equal(sloppyResult.before, 'same-value');
      assert.equal(sloppyResult.after, 'constant');
      fieldMarks(left, sloppyResult, 'before', 'sloppy.before');
      cleanField(left, sloppyResult, 'after', 'sloppy.after');

      left.close();
      right.close();
      delete globalThis[strictKey];
    } finally {
      delete globalThis[strictKey];
      await rm(root, { recursive: true, force: true });
    }
  }
);

test('property writes preserve RHS, key conversion and null-receiver order', () => {
  const source = `module.exports = function() {
    const log = []; let name = 'before'; const target = {};
    const key = {toString() { log.push('key'); return name; }};
    target[key] = (log.push('rhs'), name = 'after', 42);
    target[key] += (log.push('compound-rhs'), name = 'last', 1);
    target[key]++;
    try { null[key] = (log.push('null-rhs'), 1); } catch (error) { log.push(error.name); }
    const broken = {toString() { log.push('throw-key'); throw RangeError('key'); }};
    try { target[broken] = (log.push('throw-rhs'), 1); } catch (error) { log.push(error.name); }
    return {log, target};
  };`;
  const load = code => {
    const module = { exports: {} };
    new Function('module', code)(module);
    return module.exports;
  };
  const expected = load(source)();
  const instrumented = load(
    transform(source, '/tmp/write-order.cjs', undefined, undefined, 'commonjs')
      .code
  );
  const state = new SecurityState(identity('write-order'));
  try {
    assert.deepEqual(instrumented(), expected);
    assert.deepEqual(bind(state, instrumented), expected);
  } finally {
    state.close();
  }
});

test('direct eval retains helper-named bindings in parameters and enclosing scopes', () => {
  const sources = [
    `module.exports = function(Symbol) { return eval('Symbol'); };`,
    `module.exports = function(globalThis) { return eval('globalThis'); };`,
    `const Symbol = 42; module.exports = function() { return eval('Symbol'); };`,
    `module.exports = function(globalThis) { return (() => eval('globalThis'))(); };`,
  ];
  for (const source of sources) {
    const result = transform(
      source,
      '/tmp/eval-binding.cjs',
      undefined,
      undefined,
      'commonjs'
    );
    assert.ok(result.gaps.includes('direct_eval_helper_binding'));
    const module = { exports: {} };
    new Function('module', result.code)(module);
    const state = new SecurityState(identity('eval-binding'));
    try {
      assert.equal(module.exports(42), 42);
      assert.equal(
        bind(state, () => module.exports(42)),
        42
      );
    } finally {
      state.close();
    }
  }
});

test('wide source capture bounds descriptor reads and never invokes accessors', () => {
  const state = new SecurityState(identity('wide-capture'));
  const input = Object.fromEntries(
    Array.from({ length: 50000 }, (_, i) => ['field' + i, 'request-value'])
  );
  Object.defineProperty(input, 'field0', {
    enumerable: true,
    get() {
      throw new Error('business getter');
    },
  });
  const original = Object.getOwnPropertyDescriptor;
  const allDescriptors = Object.getOwnPropertyDescriptors;
  let reads = 0;
  Object.getOwnPropertyDescriptor = (object, key) => {
    if (object === input) reads++;
    return original(object, key);
  };
  Object.getOwnPropertyDescriptors = object => {
    if (object === input) reads += Object.keys(object).length;
    return allDescriptors(object);
  };
  try {
    state.capture(input, 'http.request.body', 'body');
    assert.ok(reads <= 128);
    assert.ok(state.gaps.has('source_field_limit'));
    assert.ok(state.gaps.has('source_accessor_unsupported'));
    assert.ok(state.field(input, 'field1').length);
    assert.equal(state.field(input, 'field49999').length, 0);
  } finally {
    Object.getOwnPropertyDescriptor = original;
    Object.getOwnPropertyDescriptors = allDescriptors;
    state.close();
  }
});

test('cached settled promises and resolvers release inputs captured by executors, calls and accessors', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-promise-retention-'));
  try {
    const { file } = await loadTransformed(
      root,
      'retention',
      `
      export function start(payload) {
        const task = async () => { await 0; return payload.value; };
        const box = {get task() { return (async () => { await 0; return payload.value; })(); }};
        return [task(), box.task];
      }
      export function deferred(payload, rejected) {
        let settle;
        const promise = new Promise((resolve, reject) => {
          settle = rejected ? reject : resolve;
          if (payload.value < 0) throw new Error('unexpected payload');
        });
        settle(payload.value);
        return {settle, promise};
      }
    `
    );
    const source = `
      import assert from 'node:assert/strict';
      import * as values from ${JSON.stringify(new URL('../src/core/values.mjs', import.meta.url).href)};
      import * as calls from ${JSON.stringify(new URL('../src/core/calls.mjs', import.meta.url).href)};
      import * as operations from ${JSON.stringify(new URL('../src/core/operations.mjs', import.meta.url).href)};
      import {SecurityState} from ${JSON.stringify(new URL('../src/core/state.mjs', import.meta.url).href)};
      import {bind} from ${JSON.stringify(new URL('../src/core/runtime.mjs', import.meta.url).href)};
      globalThis[Symbol.for('beacon.security.helpers.v1')] = {...values, ...calls, ...operations};
      const {start, deferred} = await import(${JSON.stringify(pathToFileURL(file).href)});
      const state = new SecurityState(${JSON.stringify(identity('retention'))});
      function request(value) {
        const input = {value, data: Buffer.alloc(1024 * 1024)};
        return {ref: new WeakRef(input), promises: bind(state, () => start(input)),
          resolved: bind(state, () => deferred(input, false)), rejected: bind(state, () => deferred(input, true))};
      }
      const cache = Array.from({length: 8}, (_, i) => request(i));
      assert.deepEqual(await Promise.all(cache.flatMap(item => item.promises)), Array.from({length: 8}, (_, i) => [i, i]).flat());
      assert.deepEqual(await Promise.all(cache.map(item => item.resolved.promise)), Array.from({length: 8}, (_, i) => i));
      assert.deepEqual(await Promise.all(cache.map(item => item.rejected.promise.catch(value => value))), Array.from({length: 8}, (_, i) => i));
      state.close();
      for (let i = 0; i < 8; i++) { await new Promise(setImmediate); global.gc(); }
      assert.equal(cache.filter(item => item.ref.deref()).length, 0);
      assert.equal(cache.flatMap(item => item.promises).length, 16);
      for (const item of cache) { item.resolved.settle(99); item.rejected.settle(99); }
      assert.deepEqual(await Promise.all(cache.map(item => item.resolved.promise)), Array.from({length: 8}, (_, i) => i));
    `;
    execFileSync(
      process.execPath,
      ['--expose-gc', '--input-type=module', '--eval', source],
      { timeout: 20000 }
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('URL models preserve business getters and retain standard URL propagation', async () => {
  installBuiltins();
  const root = await mkdtemp(join(tmpdir(), 'security-url-observation-'));
  const state = new SecurityState(identity('url-observation'));
  try {
    const { module: fixture } = await loadTransformed(
      root,
      'url-observation',
      `
      export function read(value) { return String(value); }
      export function construct(input) { return String(new URL(input.url)); }
    `
    );
    for (const active of [false, true]) {
      const run = fn => (active ? bind(state, fn) : fn());
      let reads = 0;
      class BusinessURL extends URL {
        get hostname() {
          reads++;
          throw new Error('unrequested getter');
        }
      }
      const derived = new BusinessURL('https://example.com/path');
      assert.equal(
        run(() => fixture.read(derived)),
        'https://example.com/path'
      );
      const own = new URL('https://example.com/own');
      Object.defineProperty(own, 'hostname', {
        get() {
          reads++;
          throw new Error('unrequested own getter');
        },
      });
      assert.equal(
        run(() => fixture.read(own)),
        'https://example.com/own'
      );
      const proxy = new Proxy(
        {
          [Symbol.toPrimitive]() {
            return 'proxy-value';
          },
        },
        {
          getPrototypeOf() {
            reads++;
            throw new Error('unrequested prototype');
          },
        }
      );
      assert.equal(
        run(() => fixture.read(proxy)),
        'proxy-value'
      );
      assert.equal(reads, 0);
    }
    const input = { url: 'https://example.com/tainted-value' };
    state.capture(input, 'http.request.parameter', 'url');
    const result = bind(state, () =>
      calls.invoke(values.p(fixture.construct), [values.p(input)])
    );
    assert.equal(result.v, input.url);
    assert.ok(result.m.length);
    assert.ok(state.gaps.has('unmodeled_url_carrier'));
    assert.ok(state.gaps.has('unmodeled_url_property'));
  } finally {
    state.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('object spread bounds observation and removes marks overwritten by clean fields', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-spread-'));
  const state = new SecurityState(identity('spread'));
  const original = Object.getOwnPropertyDescriptor,
    all = Object.getOwnPropertyDescriptors;
  try {
    const { module: fixture } = await loadTransformed(
      root,
      'spread',
      `
      export function merge(left, right) { return {...left, ...right}; }
    `
    );
    const wide = Object.fromEntries(
      Array.from({ length: 50000 }, (_, i) => ['field' + i, 'clean'])
    );
    const marked = {
      field0: 'request',
      field49999: 'request',
      kept: 'request',
      0: 'request',
    };
    state.capture(marked, 'http.request.body', 'body');
    let reads = 0,
      getterCalls = 0;
    Object.getOwnPropertyDescriptor = (value, key) => {
      if (value === wide) reads++;
      return original(value, key);
    };
    Object.getOwnPropertyDescriptors = value => {
      if (value === wide) reads += Object.keys(value).length;
      return all(value);
    };
    bind(state, () => {
      const result = fixture.merge(marked, wide);
      assert.equal(result.field0, 'clean');
      assert.equal(state.field(result, 'field0').length, 0);
      assert.equal(state.field(result, 'field49999').length, 0);
      assert.ok(state.field(result, 'kept').length);
      assert.ok(reads <= 512);
      reads = 0;
      fixture.merge({}, wide);
      assert.equal(reads, 0);
      const accessor = {
        get kept() {
          getterCalls++;
          return 'clean';
        },
      };
      assert.equal(
        state.field(fixture.merge(marked, accessor), 'kept').length,
        0
      );
      assert.equal(getterCalls, 1);
      assert.equal(state.field(fixture.merge(marked, 'safe'), '0').length, 0);
      const symbol = Symbol('input');
      const input = { [symbol]: 'request' };
      state.putField(
        input,
        symbol,
        state.source('request', 'http.request.body', 'symbol')
      );
      assert.ok(state.field(fixture.merge({}, input), symbol).length);
      const many = Object.fromEntries(
        Array.from({ length: 300 }, (_, i) => ['k' + i, 'request'])
      );
      const marks = state.source('request', 'http.request.body', 'many');
      for (const key of Object.keys(many)) state.putField(many, key, marks);
      const limited = fixture.merge({}, many);
      assert.equal(Object.keys(limited).length, 300);
      assert.ok(state.gaps.has('object_spread_field_limit'));
      assert.equal(state.record(limited)?.fields.size, 0);
    });
  } finally {
    Object.getOwnPropertyDescriptor = original;
    Object.getOwnPropertyDescriptors = all;
    state.close();
    await rm(root, { recursive: true, force: true });
  }
});
