import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

process.env.BEACON_SECURITY_ENABLED = 'true';
process.env.BEACON_SECURITY_NODE_INCLUDE = process.cwd();
process.env.BEACON_SECURITY_SBOM_ENABLED = 'false';
const rt = await import('../src/core/runtime.mjs');
const { SecurityState } = await import('../src/core/state.mjs');
const { collectionConfigured } = await import('../src/config.mjs');
const { transform } = await import('../src/transform/index.mjs');
const values = await import('../src/core/values.mjs');
const operations = await import('../src/core/operations.mjs');
const calls = await import('../src/core/calls.mjs');
const { installBuiltins, installLibrary } = await import(
  '../src/adapters/sinks.mjs'
);
installBuiltins();
let pairs = 0;
globalThis[Symbol.for('beacon.security.helpers.v1')] = {
  ...values,
  ...operations,
  ...calls,
  p(...args) {
    pairs++;
    return values.p(...args);
  },
};
const root = await mkdtemp(join(tmpdir(), 'beacon-performance-stack-'));
const filename = join(root, 'fixture.mjs');
const source = `
  import {promisify} from 'node:util';
  let enclosing = 'old';
  export function outside(user) { return user.profile.name.trim(); }
  export async function outsideAsync(user) { await Promise.resolve(); return user.profile.name.trim(); }
  export function closure(value) { return () => value.trim(); }
  export function writeOuter(value) { enclosing = value; return enclosing; }
  export function bound(fn) { return fn.bind(null); }
  export function promised(fn) { return promisify(fn); }
  export function factory(factory, fn) { return factory(fn); }
  export function a(kind) { return b(kind); }
  function b(kind) { return c(kind); }
  function c(kind) { return d(kind); }
  function d(kind) { return e(kind); }
  function e(kind) {
    if (kind === 'getter') { const value = { get fail() { throw new Error('getter'); } }; return value.fail; }
    if (kind === 'native') return JSON.parse('!');
    if (kind === 'subclass') { class ApplicationError extends Error {} throw new ApplicationError('subclass'); }
    throw new Error(kind === 'multiline' ? 'first line\\nsecond line' : 'probe');
  }
  export async function asyncFailure() { await Promise.resolve(); return a(); }
`;
await writeFile(
  filename,
  transform(source, filename, pathToFileURL(filename).href).code
);
const fixture = await import(pathToFileURL(filename));
const keepAlive = setInterval(() => {}, 1000);
after(async () => {
  await rt.shutdown();
  clearInterval(keepAlive);
  await rm(root, { recursive: true, force: true });
});

test('inactive synchronous work avoids boxed expressions but escaping closures remain instrumented', () => {
  const user = { profile: { name: ' Alice ' } };
  pairs = 0;
  for (let i = 0; i < 1000; i++) assert.equal(fixture.outside(user), 'Alice');
  assert.equal(pairs, 0);
  const state = new SecurityState({
    application_id: 'perf',
    instance_id: 'perf',
  });
  state.capture(user, 'http.request.body', 'body');
  try {
    rt.bind(state, () => {
      const result = calls.invoke(values.p(fixture.outside), [values.p(user)]);
      assert.ok(result.m.length);
      assert.ok(pairs > 0);
    });
    pairs = 0;
    const escaped = fixture.closure(' Alice ');
    assert.equal(escaped(), 'Alice');
    assert.ok(pairs > 0);
    assert.equal(fixture.writeOuter('new'), 'new');
  } finally {
    state.close();
  }
});

test('expression checks do not repeatedly read environment while admission and pause remain live', () => {
  rt.start();
  collectionConfigured();
  const original = process.env;
  let reads = 0;
  const state = new SecurityState({
    application_id: 'perf',
    instance_id: 'perf',
  });
  process.env = new Proxy(original, {
    get(target, name) {
      if (name === 'BEACON_SECURITY_ENABLED') reads++;
      return Reflect.get(target, name);
    },
  });
  try {
    rt.bind(state, () => {
      for (let i = 0; i < 10000; i++) assert.equal(rt.current(), state);
      assert.equal(reads, 0);
      rt.getRuntime().exporter.ledger.policy.paused = true;
      assert.equal(rt.current(), undefined);
      assert.equal(rt.hasRequestContext(), true);
      rt.getRuntime().exporter.ledger.policy.paused = false;
      assert.equal(rt.current(), state);
    });
    original.BEACON_SECURITY_ENABLED = 'false';
    assert.equal(collectionConfigured(), false);
    original.BEACON_SECURITY_ENABLED = 'true';
    assert.equal(collectionConfigured(), true);
  } finally {
    process.env = original;
    state.close();
  }
});

test('inactive async continuations avoid boxing while request-bound continuations retain taint', async () => {
  const user = { profile: { name: ' Alice ' } };
  pairs = 0;
  for (let i = 0; i < 100; i++)
    assert.equal(await fixture.outsideAsync(user), 'Alice');
  assert.equal(pairs, 0);
  const state = new SecurityState({
    application_id: 'async-performance',
    instance_id: 'async-performance',
  });
  state.capture(user, 'http.request.body', 'body');
  try {
    await rt.bind(state, async () => {
      const result = calls.invoke(values.p(fixture.outsideAsync), [
        values.p(user),
      ]);
      const value = await result.v;
      assert.equal(value, 'Alice');
      assert.ok(calls.awaited(result, value).m.length);
      assert.ok(pairs > 0);
    });
  } finally {
    state.close();
  }
});

test('factories called outside requests retain models when their functions are later invoked inside one', async () => {
  const { promisify } = await import('node:util');
  const fs = {
    readFile(path, callback) {
      callback(null, 'contents');
    },
  };
  installLibrary('node:fs', fs);
  for (const [factory, callback] of [
    [fn => fixture.bound(fn), true],
    [fn => fixture.promised(fn), false],
    [fn => fixture.factory(promisify, fn), false],
  ]) {
    const fn = factory(fs.readFile);
    const state = new SecurityState({
      application_id: 'factory',
      instance_id: 'factory',
    });
    try {
      await rt.bind(state, async () => {
        const input = '/synthetic/path';
        const args = [
          values.p(
            input,
            state.source(input, 'http.request.parameter', 'path')
          ),
        ];
        if (callback) args.push(values.p(() => {}));
        await calls.invoke(values.p(fn), args).v;
        assert.equal(state.pending.length, 1);
        assert.equal(state.pending[0].rule, 'path_traversal');
      });
    } finally {
      state.close();
    }
  }
});

test('ordinary, getter, native, subclass and asynchronous errors retain business callers', async () => {
  const limit = Error.stackTraceLimit;
  const state = new SecurityState({
    application_id: 'stack',
    instance_id: 'stack',
  });
  try {
    Error.stackTraceLimit = 10;
    for (const kind of [
      'ordinary',
      'getter',
      'native',
      'subclass',
      'multiline',
    ]) {
      assert.throws(
        () => rt.bind(state, () => fixture.a(kind)),
        error => {
          const stack = error.stack;
          if (kind === 'multiline')
            assert.match(stack, /^Error: first line\nsecond line\n/);
          for (const name of ['a', 'b', 'c', 'd', 'e'])
            assert.match(
              stack,
              new RegExp(`\\b${name} \\(`),
              `${kind}: ${stack}`
            );
          assert.equal(
            stack.includes('/src/core/'),
            false,
            `${kind}: ${stack}`
          );
          return true;
        }
      );
      assert.equal(Error.stackTraceLimit, 10);
    }
    await assert.rejects(
      rt.bind(state, () => fixture.asyncFailure()),
      error => {
        assert.match(error.stack, /asyncFailure/);
        assert.equal(error.stack.includes('/src/core/'), false);
        return true;
      }
    );
    Error.stackTraceLimit = 0;
    assert.throws(
      () => rt.bind(state, () => fixture.a()),
      error => error.stack === 'Error: probe'
    );
  } finally {
    Error.stackTraceLimit = limit;
    state.close();
  }
});

test('application stack formatting and explicit stack assignment remain owned by the application', () => {
  const descriptor = Object.getOwnPropertyDescriptor(
    Error,
    'prepareStackTrace'
  );
  let callsToHook = 0;
  Error.prepareStackTrace = (error, sites) => {
    callsToHook++;
    return sites;
  };
  try {
    assert.throws(
      () => fixture.a(),
      error => Array.isArray(error.stack)
    );
    assert.equal(callsToHook, 1);
  } finally {
    if (descriptor)
      Object.defineProperty(Error, 'prepareStackTrace', descriptor);
    else delete Error.prepareStackTrace;
  }
  assert.throws(
    () => fixture.a(),
    error => {
      error.stack = 'application stack';
      assert.equal(error.stack, 'application stack');
      return true;
    }
  );
});
