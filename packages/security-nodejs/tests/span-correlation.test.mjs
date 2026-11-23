import assert from 'node:assert/strict';
import test from 'node:test';
import { trace } from '@opentelemetry/api';
import { SecurityState } from '../src/core/state.mjs';
import { onlineEvent } from '../src/schema.mjs';

process.env.BEACON_SECURITY_ENABLED = 'true';
process.env.BEACON_SECURITY_NODE_INCLUDE = process.cwd();

for (const current of [undefined, 'b'.repeat(16), 'c'.repeat(16)]) {
  test(`detection retains the active invocation span (${current || 'absent'})`, t => {
    const spanContext = {
      traceId: 'a'.repeat(32),
      spanId: current,
      traceFlags: 3,
    };
    t.mock.method(trace, 'getActiveSpan', () =>
      current ? { spanContext: () => spanContext } : undefined
    );
    const state = new SecurityState({
      application_id: 'span-test',
      instance_id: '11111111-1111-4111-8111-111111111111',
    });
    state.trace_id = spanContext.traceId;
    state.server_span_id = 'b'.repeat(16);
    try {
      const marks = state.source('q', 'http.request.parameter', 'q');
      const event = onlineEvent(
        state.sink(
          'sql_injection',
          'template',
          'query',
          'span-test#query',
          marks
        )
      );
      assert.equal(event.span_id, current);
      assert.equal(event.trace_flags, current ? 3 : undefined);
      assert.equal(Object.hasOwn(event, 'server_span_id'), false);
      assert.equal(Object.hasOwn(event, 'current_span_id'), false);
    } finally {
      state.close();
    }
  });
}
