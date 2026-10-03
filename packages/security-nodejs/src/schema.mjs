import { createHash } from 'node:crypto';
import { runtimeIdentity } from './config.mjs';

export const SCHEMA_VERSION = 1;
export const PRODUCT = 'io.beacon.security';
export const FINGERPRINT_VERSION = 1;

export function sinkFields(rule, role, fn, location) {
  const aliases = {
    template: 'sql_template',
    shell: 'shell_script',
    shell_command: 'shell_script',
    argv: 'argument',
    ordinary_argument: 'argument',
    unknown_target: 'destination_unknown',
    request_path: 'path_or_query',
    request_query: 'path_or_query',
    path_query: 'path_or_query',
  };
  const sink = {
    function: fn,
    role: aliases[role] || role,
    location,
    operation: '',
    path_role: '',
    input_part: '',
  };
  if (rule === 'http_request_input')
    sink.input_part =
      role === 'request_path'
        ? 'path'
        : role === 'request_query'
          ? 'query'
          : 'path_or_query';
  if (rule === 'path_traversal') {
    sink.role = 'file_path';
    const name = fn.toLowerCase();
    let operation = 'unknown';
    if (/copy|\.cp(?:sync)?$|\.link(?:sync)?$/.test(name)) operation = 'copy';
    else if (/rename|\.move$/.test(name)) operation = 'rename';
    else if (/delete|unlink|rmdir|\.rm(?:sync)?$/.test(name))
      operation = 'delete';
    else if (['read', 'write', 'delete', 'rename'].includes(role))
      operation = role;
    else if (
      role === 'source' ||
      /inputstream|reader|directorystream|\.read/.test(name)
    )
      operation = 'read';
    else if (role === 'target' || /outputstream|writer|\.write/.test(name))
      operation = 'write';
    sink.operation = operation;
    sink.path_role = 'unknown';
    if (role === 'source' || role === 'read') sink.path_role = 'source';
    else if (['target', 'write', 'delete', 'destination_path'].includes(role))
      sink.path_role = 'target';
    else if (
      role === 'file_path' &&
      ['copy', 'rename', 'read'].includes(operation)
    )
      sink.path_role = 'source';
    else if (role === 'file_path' && ['write', 'delete'].includes(operation))
      sink.path_role = 'target';
  }
  return sink;
}

export function findingFingerprint(
  applicationId,
  language,
  rule,
  sink,
  signatures
) {
  const hash = createHash('sha256');
  const parts = [
    '1',
    applicationId,
    language,
    rule,
    sink.role,
    sink.function,
    sink.location,
    sink.operation,
    sink.path_role,
    sink.input_part,
    ...[...new Set(signatures)].sort(),
  ];
  for (const part of parts) {
    const value = Buffer.from(String(part), 'utf8');
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(value.length);
    hash.update(length).update(value);
  }
  return 'finding-' + hash.digest('hex');
}

export function traceId(value, length) {
  const text = String(value || '').toLowerCase();
  return text.length === length &&
    /^[0-9a-f]+$/.test(text) &&
    !/^0+$/.test(text)
    ? text
    : '';
}

export function componentReference(value = {}, applicationId = '') {
  value ||= {};
  return {
    status: value.status || 'unresolved',
    sbom_id: value.sbom_id || '',
    revision: value.revision ?? null,
    release_id: value.release_id || '',
    application_id: value.application_id || applicationId,
    'bom-ref': value['bom-ref'] || '',
    reason:
      value.reason ||
      (value.status === 'resolved' ? '' : 'component_not_resolved'),
    observed_url: value.observed_url || '',
    query: value.query || '',
  };
}

export function requestFields(value = {}) {
  return {
    method: '',
    route: '',
    route_status: 'unavailable',
    status_code: null,
    started_at: null,
    ended_at: null,
    framework: '',
    transport: '',
    error_type: '',
    ...value,
  };
}

export function eventRecord(input, identity = {}) {
  const event = { ...input };
  const source = {
    application_id: '',
    instance_id: '',
    service: {},
    code: { repository: '', commit: '', build_id: '', service_version: '' },
    runtime: runtimeIdentity(),
    identity_status: 'incomplete',
    ...identity,
    ...(event.identity || {}),
  };
  delete event.identity;
  for (const field of [
    'application_id',
    'instance_id',
    'service',
    'code',
    'runtime',
    'identity_status',
  ]) {
    if (event[field] === undefined && source[field] !== undefined)
      event[field] = source[field];
  }
  event.schema_version = SCHEMA_VERSION;
  event.source =
    event.event_name === 'beacon.security.sbom.snapshot' ||
    String(event.event_name).startsWith('beacon.security.sbom.')
      ? 'beacon_security_sbom'
      : 'beacon_security';
  event.observed_at ||= new Date().toISOString();
  if (
    event.event_name === 'beacon.security.finding' ||
    event.event_name === 'beacon.security.collection.incomplete'
  ) {
    event.request = requestFields(event.request);
    event.trace_id = traceId(event.trace_id, 32);
    event.server_span_id = event.trace_id
      ? traceId(event.server_span_id, 16)
      : '';
    event.current_span_id = event.trace_id
      ? traceId(event.current_span_id, 16)
      : '';
    event.trace_flags = event.server_span_id
      ? (Number(event.trace_flags) || 0) & 0xff
      : 0;
    event.trace_availability = 'not_guaranteed_by_trace_id';
  }
  if (event.event_name === 'beacon.security.finding') {
    event.component = componentReference(event.component, event.application_id);
    event.stack ||= [];
  }
  if (event.event_name === 'beacon.security.collection.incomplete') {
    event.counts = {
      objects: null,
      nodes: null,
      sources: null,
      findings: null,
      retained_bytes: null,
      ...event.counts,
    };
    event.collection_status ||= 'unknown';
  }
  if (event.event_name === 'beacon.security.sbom.snapshot') {
    event.status ||= 'current';
    event.dropped_observations ??= 0;
  }
  if (event.event_name === 'beacon.security.sbom.health') {
    const defaults = {
      sbom_id: '',
      revision: 0,
      release_id: '',
      status: 'initializing',
      last_refresh_at: null,
      last_failure_at: null,
      last_error_type: null,
      current_components: null,
      history_count: null,
      completeness: 'incomplete',
      reasons: [],
      dropped_observations: 0,
    };
    for (const [key, value] of Object.entries(defaults))
      if (event[key] === undefined) event[key] = value;
  }
  return event;
}
