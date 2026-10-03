import { eventRecord, requestFields } from '../schema.mjs';
import {
  VERSION,
  RULES,
  collectionConfigured,
  flag,
  limit,
  supportedRuntime,
} from '../config.mjs';

const UNSET = Symbol('unset');

function now() {
  return new Date().toISOString();
}

function number(value, fallback = 0) {
  if (typeof value === 'boolean') return value ? 1 : 0;
  const result = Number(value);
  return Number.isFinite(result) ? Math.trunc(result) : fallback;
}

function text(value, fallback = '') {
  return value === undefined || value === null ? fallback : String(value);
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function copy(value) {
  if (value === undefined) return undefined;
  try {
    return structuredClone(value);
  } catch {
    try {
      return JSON.parse(
        JSON.stringify(value, (_key, item) => {
          if (item instanceof Set) return [...item];
          if (typeof item === 'bigint') return `${item}n`;
          return item;
        })
      );
    } catch {
      if (Array.isArray(value)) return value.slice();
      if (record(value)) return { ...value };
      return value;
    }
  }
}

function jsonBytes(value) {
  try {
    return Buffer.byteLength(
      JSON.stringify(value, (_key, item) => {
        if (item instanceof Set) return [...item];
        if (typeof item === 'bigint') return `${item}n`;
        return item;
      }) || 'null'
    );
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

function validUntil(value) {
  const parsed = Date.parse(text(value));
  return Number.isFinite(parsed) && parsed > Date.now();
}

function parseTime(value) {
  const parsed = Date.parse(text(value));
  if (!Number.isFinite(parsed)) throw new Error('invalid_expiry');
  return parsed;
}

function boundedError(error) {
  const name = error && error.name ? String(error.name) : 'Error';
  const message = error && error.message ? `:${String(error.message)}` : '';
  return `${name}${message}`.slice(0, 256);
}

function increment(target, key, amount = 1) {
  target[key] = number(target[key]) + number(amount);
}

function stateGaps(state) {
  const gaps = state?.gaps;
  if (gaps instanceof Set) return [...gaps].map(String).sort();
  if (Array.isArray(gaps)) return [...new Set(gaps.map(String))].sort();
  if (record(gaps)) return Object.keys(gaps).sort();
  return [];
}

function addStateGap(state, reason) {
  if (state && typeof state.gap === 'function') {
    try {
      state.gap(reason);
      return;
    } catch {
      // A diagnostic path must not affect request completion.
    }
  }
  if (state?.gaps instanceof Set) state.gaps.add(text(reason).slice(0, 256));
}

function eventSources(event) {
  return Array.isArray(event?.sources) ? event.sources : [];
}

export class RuntimeLedger {
  constructor(identity = {}, profile = '', output = '') {
    this.identity = copy(record(identity) ? identity : {});
    this.profile = text(profile);
    this.output = text(output);
    this.findings = new Map();
    this.runs = new Map();
    this.runSnapshots = new WeakMap();
    this.sharedCounters = new WeakSet();
    this.counterSizes = new WeakMap();
    this.runCounterBytes = 0;
    this.maxRunCounterBytes = limit(
      'beacon.security.runs.max.bytes',
      8 * 1024 * 1024
    );
    this.counts = Object.create(null);
    this.policy = {};
    this.sbomState = { status: 'initializing' };
    this.lastDelivery = {};
    this.startTime = now();
    this.activeRequests = 0;
    this.completedRequests = 0;
    this.findingBytes = 0;
    this.findingsRevision = 0;
    this.runsRevision = 0;
    this.writtenRevisions = { findings: -1, runs: -1 };
    this.pauseGeneration = 0;
    this.appliedRevision = '';
    this.controlError = '';
    this.controlErrorRevision = '';
    this.snapshotFailures = 0;
    this.summaryAt = 0;
    this.snapshotAt = 0;
    this.lastSnapshotFailureLog = 0;
    this.requestSecond = 0;
    this.requestsThisSecond = 0;
    this.globalGaps = new Set();
    this.maxFindings = limit('beacon.security.findings.max', 4096);
    this.maxRuns = limit('beacon.security.runs.max', 256);
    this.sampleMillis =
      limit('beacon.security.findings.sample.seconds', 300) * 1000;
    this.maxFindingBytes = limit(
      'beacon.security.findings.max.bytes',
      32 * 1024 * 1024
    );
    this.maxActive = limit('beacon.security.max.active.requests', 256);
    this.requestsPerSecond = limit('beacon.security.requests-per-second', 1000);
  }

  enabled() {
    return collectionConfigured() && !this.paused();
  }

  paused() {
    return this.policy.paused === true;
  }

  count(name, amount = 1) {
    const key = text(name);
    this.counts[key] = number(this.counts[key]) + number(amount);
  }

  gap(reason) {
    const value = text(reason).slice(0, 256);
    if (value && !this.globalGaps.has(value)) {
      this.globalGaps.add(value);
      this.count('instrumentation_failures');
    }
  }

  sbom(event) {
    if (!record(event)) return;
    const { dependencies, part_index, part_count, ...summary } = event;
    this.sbomState = { ...this.sbomState, ...copy(summary) };
    if (event.event_name === 'beacon.security.sbom.update_failed')
      this.sbomState.status = 'degraded';
  }

  begin(state) {
    this.activeRequests += 1;
    this.count('requests_started');
    const second = Math.floor(Date.now() / 1000);
    if (second !== this.requestSecond) {
      this.requestSecond = second;
      this.requestsThisSecond = 0;
    }
    this.requestsThisSecond += 1;
    const coverage = this._coverageConfiguration();
    const configured = coverage.configured;
    const budget =
      this.activeRequests <= this.maxActive &&
      this.requestsThisSecond <= this.requestsPerSecond;
    const generation = this.pauseGeneration;
    if (state && typeof state === 'object') {
      state.collection_generation = generation;
      state.collection_enabled = configured && !this.paused() && budget;
      state.collection_status = !configured
        ? coverage.status
        : this.paused()
          ? 'paused'
          : !budget
            ? 'budget_skipped'
            : 'enabled';
      if (typeof state.gap === 'function') {
        for (const reason of this.globalGaps) state.gap(reason);
      }
    }

    const run = this.policy.run;
    if (record(run) && validUntil(run.expires_at)) {
      state.run = copy(run);
      const runRecord = this.runs.get(text(run.run_id));
      if (runRecord) {
        increment(runRecord, 'active_requests');
        this._touchRun(runRecord);
      }
    } else if (state) {
      state.run = {};
    }
  }

  end(state) {
    this.activeRequests = Math.max(0, this.activeRequests - 1);
    this.completedRequests += 1;
    this.count('requests_completed');
    const sourceSignatures = record(state?.source_signatures)
      ? state.source_signatures
      : {};
    const riskSourceSignatures = record(state?.risk_source_signatures)
      ? state.risk_source_signatures
      : {};
    const sinkCounts = record(state?.sink_counts) ? state.sink_counts : {};
    const pending = Array.isArray(state?.pending) ? state.pending : [];
    const request = requestFields(
      copy(record(state?.request) ? state.request : {})
    );
    const runState = copy(record(state?.run) ? state.run : {});
    const sourceCount =
      number(state?.source_count) ||
      Object.values(sourceSignatures).reduce(
        (sum, value) => sum + Math.max(0, number(value)),
        0
      );
    if (sourceCount > 0) {
      this.count('sources', sourceCount);
      this.count('requests_with_sources');
    }
    if (Object.values(sinkCounts).some(value => number(value) > 0))
      this.count('requests_with_sinks');
    for (const [rule, amount] of Object.entries(sinkCounts))
      this.count(`sink.${rule}`, Math.max(0, number(amount)));
    if (state?.collection_enabled === false)
      this.count(`requests_${text(state.collection_status, 'unknown')}`);

    const generation = number(
      state?.collection_generation,
      this.pauseGeneration
    );
    const collectionEnabled = state?.collection_enabled !== false;
    if (collectionEnabled && generation !== this.pauseGeneration)
      addStateGap(state, 'collection_paused_during_request');
    const gaps = stateGaps(state);
    const incomplete =
      Boolean(state?.truncated) ||
      gaps.length > 0 ||
      (collectionEnabled &&
        (!this.enabled() || generation !== this.pauseGeneration));
    if (incomplete) this.count('requests_incomplete');

    const result = [];
    for (const original of pending) {
      if (!record(original)) continue;
      const findingKey = original.finding_id ? text(original.finding_id) : '';
      let finding = findingKey ? this.findings.get(findingKey) : undefined;
      const sampleTime = Date.now();
      const previousSample = number(finding?.last_sample_millis);
      const runId = text(runState.run_id);
      const sample =
        sampleTime - previousSample >= this.sampleMillis ||
        runId !== text(finding?.sample_run_id);
      const event = this._enrichEvent(
        original,
        state,
        request,
        runState,
        incomplete,
        gaps,
        !findingKey || sample
      );
      const findingId = event.finding_id;
      if (!findingId) {
        result.push(event);
        continue;
      }
      if (!finding) {
        if (this.findings.size >= this.maxFindings) {
          this.count('finding_capacity_dropped');
          continue;
        }
        finding = {
          finding_id: findingKey,
          rule: event.rule,
          assessment: event.assessment,
          validation: 'unvalidated',
          sink: copy(event.sink),
          first_seen: event.observed_at,
          occurrences: 0,
          last_sample_millis: 0,
        };
        this.findings.set(findingKey, finding);
      }
      increment(finding, 'occurrences');
      finding.last_seen = event.observed_at;
      finding.last_trace_id = event.trace_id;
      finding.last_evidence_id = event.evidence_id;
      finding.last_run = copy(runState);
      finding.code = copy(event.code);
      finding.request = copy(event.request);
      finding.component = copy(event.component);
      finding.triage = this._triage(findingKey);
      event.triage = copy(finding.triage);

      if (sample) {
        finding.last_sample_millis = sampleTime;
        finding.sample_run_id = runId;
        const representative = copy(event);
        const previousBytes = number(finding.representative_bytes);
        let estimate = jsonBytes(representative);
        if (
          estimate > limit('beacon.security.evidence.max.bytes', 65536) ||
          this.findingBytes - previousBytes + estimate > this.maxFindingBytes
        ) {
          for (const field of ['propagation', 'ranges', 'sources', 'stack'])
            delete representative[field];
          representative.truncated = true;
          representative.truncation_reason = 'finding_snapshot_byte_budget';
          estimate = jsonBytes(representative);
          this.count('finding_sample_truncated');
        }
        if (
          this.findingBytes - previousBytes + estimate <=
          this.maxFindingBytes
        ) {
          this.findingBytes += estimate - previousBytes;
          finding.representative_bytes = estimate;
          finding.representative = representative;
        } else {
          this.count('finding_sample_dropped');
          delete finding.representative;
          this.findingBytes = Math.max(0, this.findingBytes - previousBytes);
          finding.representative_bytes = 0;
        }
        event.occurrences_total = finding.occurrences;
        result.push(event);
      } else {
        this.count('representative_samples_suppressed');
      }
      finding.dirty = true;
      this.findingsRevision++;
    }

    const runId = runState.run_id;
    const run =
      runId === undefined || runId === null ? null : this.runs.get(text(runId));
    if (run)
      this._finishRunRequest(
        run,
        state,
        pending,
        request,
        runState,
        sourceSignatures,
        riskSourceSignatures,
        sinkCounts,
        incomplete,
        collectionEnabled
      );

    let diagnostic;
    try {
      diagnostic =
        typeof state?.diagnostics === 'function' ? state.diagnostics() : null;
    } catch {
      diagnostic = null;
      this.count('request_completion_errors');
    }
    if (incomplete && !record(diagnostic)) {
      diagnostic = {
        event_name: 'beacon.security.collection.incomplete',
        truncated: true,
        coverage_gaps: gaps,
      };
    }
    if (record(diagnostic)) {
      const event = this._enrichEvent(
        diagnostic,
        state,
        request,
        runState,
        incomplete,
        gaps
      );
      event.collection_status = text(state?.collection_status);
      result.push(event);
    }
    return result;
  }

  _enrichEvent(
    original,
    state,
    request,
    run,
    incomplete,
    gaps,
    includeDetails = true
  ) {
    const fields = { ...original };
    if (!includeDetails) {
      for (const field of ['sources', 'propagation', 'ranges', 'stack'])
        delete fields[field];
    }
    const event = copy(fields);
    Object.assign(event, copy(this.identity));
    event.request = copy(request);
    event.run = copy(run);
    event.trace_availability = 'not_guaranteed_by_trace_id';
    if (event.evidence_id !== undefined && event.evidence_id !== null)
      event.occurrence_id = event.evidence_id;
    if (event.trace_id === undefined || event.trace_id === null)
      event.trace_id = text(state?.trace_id);
    if (event.server_span_id === undefined || event.server_span_id === null)
      event.server_span_id = text(state?.server_span_id);
    if (event.trace_flags === undefined || event.trace_flags === null)
      event.trace_flags = state?.trace_flags ?? 0;
    if (incomplete) {
      event.truncated = true;
      event.coverage_gaps = [...gaps];
    }
    return eventRecord(event, this.identity);
  }

  _finishRunRequest(
    run,
    state,
    pending,
    request,
    runState,
    sourceSignatures,
    riskSourceSignatures,
    sinkCounts,
    incomplete,
    collectionEnabled
  ) {
    this._touchRun(run);
    increment(run, 'active_requests', -1);
    increment(run, 'requests');
    const sourceValues = Object.fromEntries(
      Object.entries(sourceSignatures).filter(([, value]) => number(value) > 0)
    );
    if (Object.keys(sourceValues).length) increment(run, 'source_requests');
    for (const [signature, amount] of Object.entries(sourceValues))
      this._boundedIncrement(run, 'source_signatures', signature, amount);
    const rule = text(run.rule);
    if (number(sinkCounts[rule]) > 0) increment(run, 'sink_requests');
    if (incomplete || !collectionEnabled) increment(run, 'incomplete_requests');
    if (number(request.status_code) >= 500) increment(run, 'error_requests');

    let observed = 0;
    const eventSourceCounts = Object.create(null);
    for (const event of pending) {
      if (!record(event) || text(event.rule) !== rule || !event.finding_id)
        continue;
      observed += 1;
      for (const source of eventSources(event)) {
        if (
          record(source) &&
          source.type !== undefined &&
          source.name !== undefined
        ) {
          const signature = `${source.type}|${source.name}`;
          eventSourceCounts[signature] =
            number(eventSourceCounts[signature]) + 1;
        }
      }
      const findingId = text(event.finding_id);
      this._boundedIncrement(run, 'finding_counts', findingId, 1);
    }
    if (observed) increment(run, 'observations', observed);
    const riskValues = Object.keys(eventSourceCounts).length
      ? eventSourceCounts
      : riskSourceSignatures;
    for (const [signature, amount] of Object.entries(riskValues))
      this._boundedIncrement(run, 'risk_source_signatures', signature, amount);
    if (this.profile !== text(run.instrumentation_profile))
      increment(run, 'incomplete_requests');
    run.last_request = copy(request);
    this._finishIfIdle(run);
  }

  _touchRun(run) {
    this.runSnapshots.delete(run);
    this.runsRevision++;
  }

  _boundedIncrement(run, field, key, amount) {
    let target = run[field];
    let count = this.counterSizes.get(target) || 0;
    if (!Object.hasOwn(target, key)) {
      const bytes = 64 + key.length * 2;
      if (
        count >= this.maxFindings ||
        this.runCounterBytes + bytes > this.maxRunCounterBytes
      ) {
        increment(run, 'incomplete_requests');
        this.count('run_counter_capacity_dropped');
        return;
      }
      this.runCounterBytes += bytes;
      count++;
    }
    // Published counters stay immutable until their worker transaction finishes.
    // Only a subsequently updated map needs a copy; closed runs are reused.
    if (this.sharedCounters.has(target)) run[field] = target = { ...target };
    this.counterSizes.set(target, count);
    Object.defineProperty(target, key, {
      value:
        (Object.hasOwn(target, key) ? number(target[key]) : 0) + number(amount),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }

  _finishIfIdle(run) {
    if (run.status !== 'draining' || number(run.active_requests) !== 0) return;
    run.delivery_loss = Math.max(
      number(run.delivery_loss),
      this._lossTotal() - number(run.loss_start)
    );
    run.snapshot_failures = Math.max(
      0,
      this.snapshotFailures - number(run.snapshot_failures_start)
    );
    run.status = 'closed';
    run.ended_at = now();
    this._touchRun(run);
  }

  recordDeliveryLoss(event, amount = 1) {
    if (!record(event)) return;
    const runValue = record(event.run) ? event.run : event;
    const runId = runValue.run_id;
    if (runId === undefined || runId === null) return;
    const run = this.runs.get(text(runId));
    if (!run) return;
    increment(run, 'delivery_loss', amount);
    increment(run, 'incomplete_requests', amount);
    this._touchRun(run);
  }

  recordSnapshotFailure() {
    this.snapshotFailures += 1;
    this.count('snapshot_failures');
  }

  controlFailure(revision, error) {
    this.controlErrorRevision = text(revision, 'unparsed');
    this.controlError = text(error).slice(0, 256);
  }

  tick(
    delivery = {},
    { control = UNSET, force = false, emitEvents = true } = {}
  ) {
    const monotonic = Date.now();
    if (!force && monotonic - this.snapshotAt < 1000)
      return this._emptyTick(delivery);
    this.snapshotAt = monotonic;
    this.lastDelivery = copy(record(delivery) ? delivery : {});
    if (control !== UNSET) {
      if (control === null) {
        // A missing file does not reset process state; an existing CLI file
        // always carries a revision and is applied below.
      } else {
        try {
          this.applyControl(control);
        } catch (error) {
          this.controlFailure(
            control?.revision || 'unparsed',
            boundedError(error)
          );
        }
      }
    }

    const summaries = [];
    for (const run of this.runs.values()) {
      if (run.status === 'active' && !validUntil(run.expires_at)) {
        run.status = 'draining';
        run.expired = true;
        this._touchRun(run);
      }
      this._finishIfIdle(run);
    }
    const flushDue =
      force ||
      monotonic - this.summaryAt >=
        limit('beacon.security.findings.flush.seconds', 30) * 1000;
    for (const finding of this.findings.values()) {
      const triage = this._triage(text(finding.finding_id));
      if (JSON.stringify(triage) !== JSON.stringify(finding.triage)) {
        finding.triage = triage;
        this.findingsRevision++;
      }
      if (flushDue && finding.dirty) {
        delete finding.dirty;
        summaries.push({
          event_name: 'beacon.security.finding.summary',
          observed_at: now(),
          identity: copy(this.identity),
          finding_id: finding.finding_id,
          occurrences_total: finding.occurrences,
          first_seen: finding.first_seen,
          last_seen: finding.last_seen,
          triage: copy(finding.triage),
        });
      }
    }
    if (summaries.length) this.summaryAt = monotonic;

    const findingsChanged =
      this.findingsRevision !== this.writtenRevisions.findings;
    const runsChanged = this.runsRevision !== this.writtenRevisions.runs;
    // Nested evidence belongs to the ledger and is replaced rather than
    // mutated. The worker clones bounded chunks before serializing the file.
    const findings = (findingsChanged ? [...this.findings.values()] : []).map(
      finding => {
        const value = { ...finding };
        for (const field of [
          'dirty',
          'last_sample_millis',
          'sample_run_id',
          'representative_bytes',
        ])
          delete value[field];
        return value;
      }
    );
    const runs = (runsChanged ? [...this.runs.values()] : []).map(run => {
      const cached = this.runSnapshots.get(run);
      if (cached) return cached;
      const value = { ...run };
      for (const key of [
        'finding_counts',
        'source_signatures',
        'risk_source_signatures',
      ])
        this.sharedCounters.add(run[key]);
      delete value.loss_start;
      delete value.snapshot_failures_start;
      this.runSnapshots.set(run, value);
      return value;
    });
    const events = emitEvents
      ? summaries.map(event => eventRecord(event, this.identity))
      : [];
    return {
      events,
      findings: findingsChanged ? this._envelope('findings', findings) : null,
      runs: runsChanged ? this._envelope('runs', runs) : null,
      revisions: { findings: this.findingsRevision, runs: this.runsRevision },
      health: this.health(delivery),
    };
  }

  _emptyTick(delivery) {
    return {
      events: [],
      findings: null,
      runs: null,
      health: this.health(delivery),
    };
  }

  health(delivery = this.lastDelivery) {
    const coverage = this._coverageConfiguration();
    const configured = coverage.configured;
    const effective = this.enabled();
    let status;
    if (!configured) status = coverage.status;
    else if (this.paused()) status = 'paused';
    else if (this.completedRequests === 0)
      status = this.activeRequests > 0 ? 'in_flight' : 'no_traffic';
    else if (
      number(this.counts.requests_incomplete) > 0 ||
      number(this.counts.requests_budget_skipped) > 0 ||
      number(this.counts.finding_capacity_dropped) > 0 ||
      number(this.counts.run_counter_capacity_dropped) > 0 ||
      this._lossTotal(delivery) > 0
    )
      status = 'incomplete';
    else if (number(this.counts.requests_with_sources) === 0)
      status = 'no_source_observed';
    else if (number(this.counts.requests_with_sinks) === 0)
      status = 'no_sink_observed';
    else status = 'observed';
    return {
      schema_version: 1,
      source: 'beacon_security',
      event_name: 'beacon.security.health',
      updated_at: now(),
      started_at: this.startTime,
      identity: copy(this.identity),
      version: VERSION,
      instrumentation_profile: this.profile,
      status,
      configured,
      effective,
      collection_status:
        configured && this.paused() ? 'paused' : coverage.status,
      active_requests: this.activeRequests,
      counts: { ...this.counts },
      rule_status: this._ruleStatus(),
      capabilities: [
        'http_server',
        'sql',
        'command',
        'http_client',
        'file',
        'modeled_string_propagation',
      ],
      coverage_semantics: 'observed_counters_not_vulnerability_recall',
      coverage_scope: 'modeled_calls_only',
      sbom: copy(this.sbomState),
      delivery: copy(record(delivery) ? delivery : {}),
      control_revision: this.appliedRevision,
      control_error: this.controlError,
      control_error_revision: this.controlErrorRevision,
      snapshot_failures: this.snapshotFailures,
      delivery_loss: this._lossTotal(delivery),
      retention: {
        findings_max: this.maxFindings,
        runs_max: this.maxRuns,
        run_counter_bytes_upper_bound: this.runCounterBytes,
        run_counter_bytes_max: this.maxRunCounterBytes,
        representative_bytes_upper_bound: this.findingBytes,
        representative_bytes_max: this.maxFindingBytes,
      },
      pause_semantics:
        'collection_paused_existing_instrumentation_remains_loaded_restart_without_extension_to_unload',
    };
  }

  applyControl(nextPolicy) {
    if (!record(nextPolicy)) throw new Error('control_object_required');
    const revision = text(nextPolicy.revision);
    if (!revision) throw new Error('control_revision_required');
    if (revision === this.appliedRevision) return;
    if (
      nextPolicy.paused !== undefined &&
      typeof nextPolicy.paused !== 'boolean'
    )
      throw new Error('invalid_pause');
    this._validateExceptions(nextPolicy.exceptions);
    const rawRun = nextPolicy.run === undefined ? null : nextPolicy.run;
    if (rawRun !== null) this._validateRun(rawRun);
    const newRun = rawRun === null ? null : copy(rawRun);
    const nextId = newRun ? text(newRun.run_id) : '';
    const existing = newRun ? this.runs.get(nextId) : null;
    if (existing && existing.status !== 'active')
      throw new Error('run_id_already_closed');
    if (newRun && !existing && this.runs.size >= this.maxRuns)
      throw new Error('run_capacity_restart_or_archive');

    for (const old of this.runs.values()) {
      if (old.status === 'active' && text(old.run_id) !== nextId) {
        old.status = 'draining';
        this._touchRun(old);
        this._finishIfIdle(old);
      }
    }
    if (newRun && !existing) {
      const coverage = this._coverageConfiguration();
      const configured = coverage.configured;
      const paused = nextPolicy.paused === true;
      const ruleStatus = this._ruleStatus();
      const run = {
        ...newRun,
        status: 'active',
        started_at: now(),
        identity: copy(this.identity),
        rule_enabled: ruleStatus[text(newRun.rule)] === true,
        collection_enabled: configured && !paused,
        collection_status: configured && paused ? 'paused' : coverage.status,
        loss_start: this._lossTotal(),
        snapshot_failures_start: this.snapshotFailures,
        instrumentation_profile: this.profile,
        finding_counts: {},
        source_signatures: {},
        risk_source_signatures: {},
        delivery_loss: 0,
        snapshot_failures: 0,
        requests: 0,
        source_requests: 0,
        sink_requests: 0,
        observations: 0,
        incomplete_requests: 0,
        error_requests: 0,
        active_requests: 0,
      };
      this.runs.set(nextId, run);
    }
    const oldPaused = this.paused();
    const newPaused = nextPolicy.paused === true;
    if (oldPaused !== newPaused) this.pauseGeneration += 1;
    this.policy = copy(nextPolicy);
    this.runsRevision++;
    this.appliedRevision = revision;
    this.controlError = '';
    this.controlErrorRevision = '';
  }

  _validateRun(rawRun) {
    if (!record(rawRun)) throw new Error('invalid_run');
    for (const field of ['run_id', 'case_id', 'rule', 'expires_at'])
      if (!text(rawRun[field])) throw new Error(`missing_run_${field}`);
    if (
      !validUntil(rawRun.expires_at) ||
      !this._ruleStatus()[text(rawRun.rule)]
    )
      throw new Error('invalid_run_expiry_or_rule');
    if (!record(rawRun.conditions)) throw new Error('missing_run_conditions');
    for (const field of ['suite', 'fixture'])
      if (!text(rawRun.conditions[field]).trim())
        throw new Error(`missing_condition_${field}`);
    const expected = rawRun.conditions.expected_requests;
    if (
      typeof expected !== 'number' ||
      !Number.isFinite(expected) ||
      expected <= 0
    )
      throw new Error('expected_requests_required');
  }

  _validateExceptions(value) {
    if (value === undefined || value === null) return;
    if (!Array.isArray(value) || value.length > 128)
      throw new Error('invalid_exceptions');
    for (const item of value) {
      if (!record(item) || !record(item.scope))
        throw new Error('invalid_exception');
      if (!text(item.scope.application_id) || !text(item.scope.finding_id))
        throw new Error('exception_scope_required');
      if (!text(item.reason).trim())
        throw new Error('exception_reason_required');
      if (!['accepted_risk', 'false_positive'].includes(item.decision))
        throw new Error('invalid_exception_decision');
      try {
        parseTime(item.expires_at);
      } catch {
        throw new Error('exception_expiry_required');
      }
    }
  }

  _triage(findingId) {
    if (!Array.isArray(this.policy.exceptions))
      return { decision: 'unreviewed' };
    for (const item of this.policy.exceptions) {
      if (!record(item) || !record(item.scope)) continue;
      if (
        text(item.scope.application_id) ===
          text(this.identity.application_id) &&
        text(item.scope.finding_id) === findingId &&
        validUntil(item.expires_at)
      )
        return copy(item);
    }
    return { decision: 'unreviewed' };
  }

  _ruleStatus() {
    return Object.fromEntries(
      RULES.map(rule => [
        rule,
        flag(`beacon.security.rules.${rule}.enabled`, true),
      ])
    );
  }

  _coverageConfiguration() {
    if (!flag('beacon.security.enabled', false))
      return { configured: false, status: 'disabled' };
    if (!supportedRuntime())
      return { configured: false, status: 'unsupported_runtime' };
    if (!collectionConfigured())
      return { configured: false, status: 'unconfigured' };
    return { configured: true, status: 'enabled' };
  }

  _envelope(key, values) {
    return {
      schema_version: 1,
      source: 'beacon_security',
      updated_at: now(),
      identity: copy(this.identity),
      [key]: values,
    };
  }

  _lossTotal(delivery = this.lastDelivery) {
    return (
      Math.max(
        this._deliveryLoss(delivery),
        number(this.counts.delivery_loss) + number(this.counts.delivery_failure)
      ) +
      number(this.counts.finding_capacity_dropped) +
      number(this.counts.request_completion_errors)
    );
  }

  _deliveryLoss(delivery) {
    if (!record(delivery)) return 0;
    let value = number(delivery.security_dropped ?? delivery.dropped);
    if (record(delivery.counters)) {
      for (const [name, amount] of Object.entries(delivery.counters)) {
        if (
          name.startsWith('beacon.security.') &&
          !name.startsWith('beacon.security.sbom.') &&
          (name.endsWith('failed') || name.endsWith('record_truncated'))
        )
          value += number(amount);
      }
    }
    return value;
  }
}

export default RuntimeLedger;
