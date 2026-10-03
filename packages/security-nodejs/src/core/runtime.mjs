import { AsyncLocalStorage } from 'node:async_hooks';
import path from 'node:path';
import {
  context,
  createContextKey,
  trace,
  isSpanContextValid,
} from '@opentelemetry/api';
import { getRPCMetadata, RPCType } from '@opentelemetry/core';
import {
  collectionConfigured,
  flag,
  identity,
  profile,
  text,
  instrumentationIsEnabled,
} from '../config.mjs';
import { SecurityState } from './state.mjs';
import { Exporter } from '../exporter/index.mjs';
import { SbomInventory } from '../sbom/index.mjs';

const local = new AsyncLocalStorage();
const key = createContextKey('beacon.security.request');
const gaps = new Set();
const requests = new WeakMap();
const activeStates = new Set();
const sourceFiles = new Map();
let runtime;
let stopped = false;
let shutdownPromise;
export function start(adapters = []) {
  if (runtime || stopped) return runtime;
  const id = identity();
  const output = path.resolve(
    text('beacon.security.output', './beacon-security-output/' + id.instance_id)
  );
  const exporter = new Exporter(id, profile(adapters), output);
  runtime = { identity: id, output, exporter, inventory: null, closed: false };
  if (
    flag('beacon.security.enabled', false) &&
    flag('beacon.security.sbom.enabled')
  ) {
    runtime.inventory = new SbomInventory(id, output, event => {
      exporter.emit(event);
      exporter.ledger.sbom(event);
    });
    runtime.inventory.start();
  } else exporter.ledger.sbom({ status: 'disabled' });
  for (const reason of gaps) exporter.ledger.gap(reason);
  return runtime;
}
export const getRuntime = () => runtime;
export function mapSourceFile(original, generated) {
  if (sourceFiles.size < 4096) sourceFiles.set(original, generated);
  else startupGap('source_location_map_limit');
}
export function startupGap(reason) {
  reason = String(reason).slice(0, 256);
  if (gaps.size < 32) gaps.add(reason);
  runtime?.exporter.ledger.gap(reason);
}
export function current() {
  const state = local.getStore() || context.active().getValue(key);
  if (
    !state ||
    state.closed ||
    !state.collection_enabled ||
    stopped ||
    !instrumentationIsEnabled()
  )
    return undefined;
  if (runtime && !runtime.exporter.ledger.enabled()) {
    state.gap('collection_paused_during_request');
    return undefined;
  }
  return state;
}
export function bind(state, fn) {
  return local.run(state, () =>
    context.with(context.active().setValue(key, state), fn)
  );
}
export function begin(req, res, metadata = {}) {
  if (!collectionConfigured() || !runtime || stopped) return undefined;
  const existing = requests.get(req);
  if (existing && !existing.closed) return existing;
  const state = new SecurityState(runtime.identity, metadata);
  const rpc = getRPCMetadata(context.active());
  const span = rpc?.type === RPCType.HTTP ? rpc.span : undefined;
  if (span && isSpanContextValid(span.spanContext())) {
    state.server_span = span;
    state.trace_id = span.spanContext().traceId;
    state.server_span_id = span.spanContext().spanId;
  }
  state.onFinding = event => {
    const filename = event.sink.location.split('#')[0];
    event.component = runtime.inventory?.resolve(
      sourceFiles.get(filename) || filename
    ) || { status: 'unresolved', reason: 'sbom_disabled' };
    summarize(state);
  };
  runtime.exporter.ledger.begin(state);
  if (state.collection_enabled) activeStates.add(state);
  for (const reason of gaps) state.gap(reason);
  requests.set(req, state);
  const finish = () => {
    if (state.closed) return;
    try {
      state.request.status_code = res.statusCode;
      const route = req.route?.path;
      if (typeof route === 'string') state.request.route = route;
      if (state.request.route) state.request.route_status = 'observed';
      if (!res.writableFinished) state.gap('response_aborted');
    } catch {
      state.gap('request_completion_metadata_failed');
    } finally {
      end(state);
    }
  };
  res.once('finish', finish);
  res.once('close', finish);
  res.once('error', error => {
    try {
      state.request.error_type = error?.constructor?.name || 'Error';
    } catch {
      state.request.error_type = 'Error';
    }
    finish();
  });
  return state;
}
export function summarize(state) {
  const span = state.server_span;
  if (!span?.isRecording()) return;
  if (state.pending.length) {
    span.setAttributes({
      'beacon.security.detected': true,
      'beacon.security.finding_count': state.pending.length,
      'beacon.security.types': [...new Set(state.pending.map(e => e.rule))],
      'beacon.security.finding.ids': [
        ...new Set(state.pending.map(e => e.finding_id)),
      ],
      'beacon.security.evidence.ids': state.pending.map(e => e.evidence_id),
    });
  }
  if (state.truncated) span.setAttribute('beacon.security.truncated', true);
}
export function end(state) {
  if (!state || state.closed) return;
  try {
    state.request.ended_at = new Date().toISOString();
    summarize(state);
    for (const event of runtime.exporter.ledger.end(state) || [])
      runtime.exporter.emit(event, { evidence: true });
  } catch {
    runtime.exporter.ledger.count('request_completion_errors');
  } finally {
    activeStates.delete(state);
    state.close();
  }
}
export function shutdown(options = {}) {
  return (shutdownPromise ||= closeRuntime(options));
}
async function closeRuntime({ timeoutMillis = 1500 } = {}) {
  if (!runtime || runtime.closed) {
    stopped = true;
    return;
  }
  stopped = true;
  runtime.closed = true;
  for (const state of activeStates) {
    state.gap('shutdown_during_request');
    end(state);
  }
  timeoutMillis = Number.isFinite(timeoutMillis)
    ? Math.max(1, Math.min(timeoutMillis, 60000))
    : 1500;
  const started = Date.now();
  await runtime.inventory?.close(Math.max(1, timeoutMillis / 2));
  await runtime.exporter.close(
    Math.max(1, timeoutMillis - (Date.now() - started))
  );
}
