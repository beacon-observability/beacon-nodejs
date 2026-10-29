import { createHash } from 'node:crypto';
import { runtimeIdentity } from './config.mjs';

export const SCHEMA_VERSION = 2;
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

export function componentReference(value = {}) {
  if (!value?.name) return null;
  const result = { name: value.name, version: value.version || '' };
  if (value.hash) result.hash = value.hash;
  return result;
}

// Project internal detection records at the telemetry boundary. Fingerprints
// and sampling continue to use the full record above this boundary.
export function onlineEvent(value) {
  if (value.event_name === 'beacon.security.sbom.inventory') {
    const result = {
      schema_version: 2,
      source: 'beacon_security_sbom',
      event_name: value.event_name,
      instance_id: value.instance_id,
      observed_at: value.observed_at,
      started_at: value.started_at,
      uptime_ms: value.uptime_ms,
      dependencies: value.dependencies,
    };
    if (value.part_count > 1) {
      result.part_index = value.part_index;
      result.part_count = value.part_count;
    }
    return result;
  }
  if (value.event_name !== 'beacon.security.finding') return null;
  const result = {
    schema_version: 2,
    source: 'beacon_security',
    event_name: value.event_name,
    instance_id: value.instance_id,
    observed_at: value.observed_at,
    finding_id: value.finding_id,
    fingerprint_version: value.fingerprint_version,
    occurrence_id: value.occurrence_id,
    rule: value.rule,
    attack_evidence: {
      status: value.attack_evidence?.status || 'unknown',
      reason: value.attack_evidence?.reason || 'analysis_unavailable',
    },
    sink: Object.fromEntries(
      Object.entries(value.sink || {}).filter(
        ([, item]) => item !== '' && item != null
      )
    ),
    evidence_sampled: value.evidence_sampled === true,
    collection_complete:
      value.collection_complete !== false &&
      value.truncated !== true &&
      !value.coverage_gaps?.length,
  };
  const request = Object.fromEntries(
    ['method', 'route', 'status_code', 'error_type']
      .filter(
        key => value.request?.[key] !== '' && value.request?.[key] != null
      )
      .map(key => [key, value.request[key]])
  );
  if (Object.keys(request).length) result.request = request;
  for (const key of ['trace_id', 'server_span_id', 'precision'])
    if (value[key] !== '' && value[key] != null) result[key] = value[key];
  if (value.current_span_id && value.current_span_id !== value.server_span_id)
    result.current_span_id = value.current_span_id;
  for (const key of [
    'sources',
    'propagation',
    'ranges',
    'stack',
    'coverage_gaps',
  ])
    if (value[key]?.length) result[key] = value[key];
  const component = value.component || {};
  if (component.name) {
    result.component = {
      name: component.name,
      version: component.version || '',
    };
    if (component.hash) result.component.hash = component.hash;
  }
  if (value.run && Object.keys(value.run).length) result.run = value.run;
  if (value.triage?.decision && value.triage.decision !== 'unreviewed')
    result.triage = value.triage;
  if (value.truncated === true) {
    result.truncated = true;
    if (value.truncation_reason)
      result.truncation_reason = value.truncation_reason;
  }
  if (!result.evidence_sampled && value.evidence_sample_reason)
    result.evidence_sample_reason = value.evidence_sample_reason;
  return result;
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
    event.event_name === 'beacon.security.sbom.inventory'
      ? 'beacon_security_sbom'
      : 'beacon_security';
  event.observed_at ||= new Date().toISOString();
  if (event.event_name === 'beacon.security.finding') {
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
    event.attack_evidence ||= {
      status: 'unknown',
      reason: 'analysis_unavailable',
      outcome: 'not_assessed',
    };
    event.component = componentReference(event.component, event.application_id);
    event.stack ||= [];
  }
  return event;
}
