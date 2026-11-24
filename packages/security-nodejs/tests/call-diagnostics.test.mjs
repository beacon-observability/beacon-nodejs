import assert from 'node:assert/strict';
import test from 'node:test';
import { diag, DiagLogLevel } from '@opentelemetry/api';
import { invoke } from '../src/core/calls.mjs';
import { p } from '../src/core/values.mjs';
import { bind } from '../src/core/runtime.mjs';
import { SecurityState } from '../src/core/state.mjs';

test('unknown-call diagnostics are opt-in, bounded, data-free and fail-open', () => {
  const key = 'BEACON_SECURITY_CALL_DIAGNOSTICS_ENABLED';
  const previous = process.env[key];
  const messages = [];
  let fail = false;
  diag.setLogger(
    {
      error() {},
      info() {},
      debug() {},
      verbose() {},
      warn(message) {
        if (fail) throw new Error('logger failure');
        messages.push(message);
      },
    },
    DiagLogLevel.WARN
  );
  const state = new SecurityState({
    instance_id: 'call-diagnostics',
    service: {},
  });
  const secret = 'request-content-must-not-be-logged';
  let nameReads = 0;
  const unknown = new Proxy(value => value.length, {
    get(target, key, receiver) {
      if (key === 'name') nameReads++;
      return Reflect.get(target, key, receiver);
    },
  });
  const call = site =>
    bind(state, () => {
      const input = p(
        secret,
        state.source(secret, 'http.request.parameter', 'id')
      );
      assert.equal(invoke(p(unknown), [input], site).v, secret.length);
      assert.ok(state.gaps.has('unmodeled_call_result'));
    });
  try {
    delete process.env[key];
    call('app.mjs#1:2');
    assert.deepEqual(messages, []);
    process.env[key] = 'true';
    call('app.mjs#1:2');
    call('app.mjs#1:2');
    assert.equal(messages.length, 1);
    assert.ok(messages[0].includes('app.mjs#1:2'));
    assert.ok(!messages[0].includes(secret));
    fail = true;
    call('logger-failure.mjs#1:0');
    fail = false;
    for (let i = 0; i < 100; i++) call(`app.mjs#${i + 2}:0`);
    assert.equal(messages.length, 31); // one of 32 sites had a failing logger
    assert.equal(nameReads, 0);
    state.gaps.clear();
    bind(state, () => invoke(p(unknown), [p('clean')], 'clean.mjs#1:0'));
    assert.deepEqual([...state.gaps], []);
    assert.equal(messages.length, 31);
  } finally {
    state.close();
    diag.disable();
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  }
});
