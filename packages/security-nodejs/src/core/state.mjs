import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { eventRecord, sinkFields, findingFingerprint } from '../schema.mjs';
import { trace } from '@opentelemetry/api';
import { types } from 'node:util';
import { flag, limit, runtimeIdentity } from '../config.mjs';

const object = value =>
  value !== null && (typeof value === 'object' || typeof value === 'function');
const width = value =>
  typeof value === 'string' || Buffer.isBuffer(value)
    ? value.length
    : ['number', 'boolean', 'bigint'].includes(typeof value)
      ? String(value).length
      : 0;
const ownSourceDirectory = fileURLToPath(new URL('../', import.meta.url));
let processBytes = 0;

export class SecurityState {
  constructor(identity, request = {}) {
    this.id = randomUUID();
    this.identity = identity;
    this.request = request;
    this.started_at = new Date().toISOString();
    this.request.started_at = this.started_at;
    this.request.route_status = request.route ? 'observed' : 'unavailable';
    this.trace_id = '';
    this.server_span_id = '';
    this.server_span = null;
    this.run = {};
    this.collection_enabled = true;
    this.collection_status = 'enabled';
    this.collection_generation = 0;
    this.closed = false;
    this.truncated = false;
    this.pending = [];
    this.source_signatures = {};
    this.risk_source_signatures = {};
    this.sink_counts = {};
    this.source_count = 0;
    this.gaps = new Set();
    this.sources = new Map();
    this.sourceKeys = new Map();
    this.nodes = new Map();
    this.objects = new WeakMap();
    this.objectCount = 0;
    this.bytes = 0;
    this.seen = new Set();
    this.sites = new Set();
    this.maxNodes = limit('beacon.security.max.nodes', 8192);
    this.maxObjects = limit('beacon.security.max.objects', 4096);
    this.maxMarks = limit('beacon.security.max.marks-per-object', 64);
    this.maxFindings = limit('beacon.security.max.findings', 32);
    this.maxBytes = limit('beacon.security.max.tracked.bytes', 1048576);
    this.maxProcessBytes = limit(
      'beacon.security.max.process.tracked.bytes',
      67108864
    );
  }
  gap(reason) {
    if (!this.closed && this.gaps.size < 32)
      this.gaps.add(String(reason).slice(0, 256));
  }
  diagnostics() {
    if (!this.gaps.size && !this.truncated && this.collection_enabled)
      return null;
    return {
      event_name: 'beacon.security.collection.incomplete',
      trace_id: this.trace_id,
      server_span_id: this.server_span_id,
      trace_flags: this.server_span?.spanContext().traceFlags ?? 0,
      truncated: this.truncated,
      coverage_gaps: [...this.gaps].sort(),
      collection_status: this.collection_status,
      counts: {
        objects: this.objectCount,
        nodes: this.nodes.size,
        sources: this.source_count,
        findings: this.pending.length,
        retained_bytes: this.bytes,
      },
    };
  }
  exhaust(reason) {
    this.truncated = true;
    this.gap(reason);
    return false;
  }
  reserve(bytes) {
    if (
      this.bytes + bytes > this.maxBytes ||
      processBytes + bytes > this.maxProcessBytes
    )
      return this.exhaust('tracking_byte_budget');
    this.bytes += bytes;
    processBytes += bytes;
    return true;
  }
  valid(marks = []) {
    if (this.closed || !this.collection_enabled) return [];
    const valid = [];
    for (const mark of marks || []) {
      if (mark?.state !== this.id) {
        if (mark) this.gap('expired_or_cross_request_marks');
        continue;
      }
      if (valid.length >= this.maxMarks) {
        this.exhaust('marks_per_value_limit');
        break;
      }
      valid.push(mark);
    }
    return valid;
  }
  record(value, create = false) {
    if (!object(value) || this.closed || !this.collection_enabled)
      return undefined;
    let entry = this.objects.get(value);
    if (!entry && create) {
      if (this.objectCount >= this.maxObjects || !this.reserve(128)) {
        this.exhaust('object_count_limit');
        return undefined;
      }
      entry = { marks: [], fields: new Map(), data: undefined };
      this.objects.set(value, entry);
      this.objectCount++;
    }
    return entry;
  }
  marks(value) {
    return this.valid(this.record(value)?.marks);
  }
  put(value, marks) {
    const entry = this.record(value, true);
    if (entry) entry.marks = this.valid(marks);
  }
  field(value, key) {
    return this.valid(this.record(value)?.fields.get(key));
  }
  putField(value, key, marks) {
    const entry = this.record(value, Boolean(marks?.length));
    if (!entry) return;
    if (!entry.fields.has(key) && marks?.length && !this.reserve(64)) return;
    marks = this.valid(marks);
    if (marks.length) entry.fields.set(key, marks);
    else entry.fields.delete(key);
  }
  node(source, parent, operation, location) {
    if (this.nodes.size >= this.maxNodes || !this.reserve(128)) {
      this.exhaust('propagation_node_limit');
      return null;
    }
    const id = this.nodes.size + 1;
    this.nodes.set(id, {
      id,
      parent_id: parent,
      source_id: source,
      operation,
      location: String(location || '').slice(0, 1024),
    });
    return id;
  }
  source(value, type, name, location = '') {
    if (this.closed || !this.collection_enabled) return [];
    const length = width(value);
    if (!length) return [];
    const signature = type + '|' + String(name).slice(0, 256);
    let source = this.sourceKeys.get(signature);
    if (!source) {
      if (!this.reserve(256)) return [];
      source = {
        id: 'src-' + (this.sources.size + 1),
        type,
        name: String(name).slice(0, 256),
        location: String(location).slice(0, 1024),
        value_type: Buffer.isBuffer(value) ? 'bytes' : typeof value,
        value_length: length,
      };
      this.sourceKeys.set(signature, source);
      this.sources.set(source.id, source);
      this.source_signatures[signature] = 1;
      this.source_count++;
    }
    const node = this.node(source.id, null, 'source', location);
    return node === null
      ? []
      : [
          {
            state: this.id,
            source_id: source.id,
            node_id: node,
            start: 0,
            end: length,
            exact: typeof value === 'string' || Buffer.isBuffer(value),
            unit: Buffer.isBuffer(value) ? 'byte' : 'utf16_code_unit',
          },
        ];
  }
  capture(value, type, name, location = '', depth = 0, visited = new Set()) {
    if (!object(value) || Buffer.isBuffer(value)) {
      const marks = this.source(value, type, name, location);
      if (object(value)) this.put(value, marks);
      return marks;
    }
    if (depth >= 6 || visited.size >= 512) {
      this.gap('source_traversal_limit');
      return [];
    }
    if (visited.has(value)) return [];
    visited.add(value);
    try {
      if (types.isProxy(value)) {
        this.gap('source_proxy_object');
        return [];
      }
      const prototype = Object.getPrototypeOf(value);
      if (
        !Array.isArray(value) &&
        prototype !== Object.prototype &&
        prototype !== null
      ) {
        this.gap('source_custom_object');
        return [];
      }
      const keys = Object.keys(value);
      let count = 0;
      for (const key of keys) {
        if (++count > 128) {
          this.gap('source_field_limit');
          break;
        }
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor.enumerable) continue;
        if (!('value' in descriptor)) {
          this.gap('source_accessor_unsupported');
          continue;
        }
        this.putField(
          value,
          key,
          this.capture(
            descriptor.value,
            type,
            name ? name + '.' + key : key,
            location,
            depth + 1,
            visited
          )
        );
      }
    } catch {
      this.gap('source_capture_failed');
    }
    return [];
  }
  step(
    marks,
    operation,
    location,
    { offset = 0, from = 0, to = Infinity, exact = true, length, unit } = {}
  ) {
    const result = [];
    for (const mark of this.valid(marks)) {
      let start = Math.max(mark.start, from),
        end = Math.min(mark.end, to);
      if (start >= end) continue;
      start = Math.max(0, start + offset);
      end = Math.max(start, end + offset);
      if (length !== undefined) {
        start = Math.min(start, length);
        end = Math.min(end, length);
      }
      if (start >= end) continue;
      const node = this.node(mark.source_id, mark.node_id, operation, location);
      if (node !== null)
        result.push({
          ...mark,
          node_id: node,
          start,
          end,
          exact: mark.exact && exact,
          unit: unit || mark.unit,
        });
    }
    return result;
  }
  convert(marks, value, operation, location) {
    const length = width(value);
    if (!length) return [];
    return this.valid(marks).flatMap(mark => {
      const id = this.node(mark.source_id, mark.node_id, operation, location);
      return id === null
        ? []
        : [
            {
              ...mark,
              node_id: id,
              start: 0,
              end: length,
              exact: false,
              unit: Buffer.isBuffer(value) ? 'byte' : 'utf16_code_unit',
            },
          ];
    });
  }
  sink(rule, role, fn, location, marks) {
    if (this.closed || !this.collection_enabled) return null;
    const site = rule + '|' + fn + '|' + location;
    if (!this.sites.has(site)) {
      if (this.sites.size < this.maxNodes && this.reserve(128)) {
        this.sites.add(site);
        this.sink_counts[rule] = (this.sink_counts[rule] || 0) + 1;
      } else this.exhaust('sink_site_budget');
    }
    marks = this.valid(marks);
    if (!marks.length || !flag('beacon.security.rules.' + rule + '.enabled'))
      return null;
    const sources = [...new Set(marks.map(m => m.source_id))]
      .map(id => this.sources.get(id))
      .filter(Boolean);
    const signatures = sources.map(s => s.type + '|' + s.name).sort();
    const sink = sinkFields(rule, role, fn, location);
    const fingerprint = findingFingerprint(
      this.identity.application_id,
      this.identity.runtime?.language || 'javascript',
      rule,
      sink,
      signatures
    );
    if (this.seen.has(fingerprint)) return null;
    if (this.pending.length >= this.maxFindings) {
      this.exhaust('request_finding_limit');
      return null;
    }
    this.seen.add(fingerprint);
    for (const signature of signatures)
      this.risk_source_signatures[signature] = 1;
    const graph = new Map();
    for (const mark of marks) {
      let node = this.nodes.get(mark.node_id);
      while (node && !graph.has(node.id)) {
        if (graph.size >= 128) {
          this.exhaust('evidence_graph_limit');
          break;
        }
        graph.set(node.id, node);
        node = this.nodes.get(node.parent_id);
      }
    }
    const exact = marks.every(m => m.exact);
    const current = trace.getActiveSpan()?.spanContext();
    const linked = current?.traceId === this.trace_id ? current : undefined;
    if (current && this.trace_id && !linked)
      this.gap('active_trace_differs_from_server');
    const event = eventRecord(
      {
        schema_version: 1,
        source: 'beacon_security',
        event_name: 'beacon.security.finding',
        evidence_id: 'ev-' + randomUUID(),
        finding_id: fingerprint,
        fingerprint_version: 1,
        rule,
        assessment:
          ['sql_injection', 'command_injection'].includes(rule) ||
          ['executable', 'destination_address'].includes(role)
            ? 'candidate_risk'
            : 'observation',
        validation: 'unvalidated',
        severity: 'unassigned',
        confidence: exact ? 'modeled_flow' : 'conservative_flow',
        observed_at: new Date().toISOString(),
        execution_observation: 'invocation_attempt',
        precision: exact ? 'exact' : 'conservative',
        trace_id: this.trace_id,
        server_span_id: this.server_span_id,
        current_span_id: linked?.spanId || '',
        trace_flags: this.server_span?.spanContext().traceFlags ?? 0,
        sources,
        propagation: [...graph.values()],
        ranges: marks.map(({ source_id, start, end, exact, unit }) => ({
          source_id,
          start,
          end,
          exact,
          unit,
        })),
        sink,
        runtime: runtimeIdentity(),
        stack:
          new Error().stack
            ?.split('\n')
            .slice(1)
            .map(line => line.trim().replace(/^at /, ''))
            .filter(
              line =>
                !line.includes(ownSourceDirectory) && !line.includes('node:')
            )
            .slice(0, 24) || [],
        truncated: this.truncated,
        coverage: 'modeled_calls_only',
        coverage_gaps: [...this.gaps],
        trace_availability: 'not_guaranteed_by_trace_id',
      },
      this.identity
    );
    this.pending.push(event);
    this.onFinding?.(event);
    return event;
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    processBytes = Math.max(0, processBytes - this.bytes);
    this.bytes = 0;
    this.objects = new WeakMap();
    this.nodes.clear();
    this.sources.clear();
    this.sourceKeys.clear();
    this.seen.clear();
    this.sites.clear();
    this.pending.length = 0;
    this.server_span = null;
  }
}
export const trackingBytes = () => processBytes;
