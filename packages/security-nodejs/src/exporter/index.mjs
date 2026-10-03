import { eventRecord, PRODUCT } from '../schema.mjs';
import { Worker } from 'node:worker_threads';
import { join } from 'node:path';

import { VERSION, flag, limit, text } from '../config.mjs';
import { RuntimeLedger } from './ledger.mjs';

function isRecord(value) {
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
      return Array.isArray(value)
        ? value.slice()
        : isRecord(value)
          ? { ...value }
          : value;
    }
  }
}

function asText(value, fallback = '') {
  return value === undefined || value === null ? fallback : String(value);
}

function encode(value) {
  return JSON.stringify(value, (_key, item) => {
    if (item instanceof Set) return [...item];
    if (typeof item === 'bigint') return `${item}n`;
    return item;
  });
}

function isoFromSeconds(value) {
  if (!value) return null;
  try {
    return new Date(value * 1000).toISOString();
  } catch {
    return null;
  }
}

function errorText(error) {
  const name = error && error.name ? String(error.name) : 'Error';
  const message = error && error.message ? `:${String(error.message)}` : '';
  return `${name}${message}`.slice(0, 256);
}

function sleep(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

function withTimeout(promise, timeoutMillis) {
  const timeout = Math.max(0, Number(timeoutMillis) || 0);
  if (timeout === 0) return Promise.reject(new Error('exporter_close_timeout'));
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error('exporter_close_timeout')),
      timeout
    );
  });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

export class Exporter {
  constructor(identity = {}, profile = '', output = '') {
    this.identity = isRecord(identity) ? copy(identity) : {};
    this.profile = asText(profile);
    this.output =
      asText(output) ||
      text(
        'beacon.security.output',
        `./beacon-security-output/${this.identity.instance_id || 'unknown'}`
      );
    this.localOutputEnabled = flag(
      'beacon.security.local-output.enabled',
      false
    );
    this.controlPath =
      text('beacon.security.control.file', '') ||
      join(this.output, 'control.json');
    this.evidencePath = text('beacon.security.evidence.file', '');
    this.maxBytes = limit('beacon.security.evidence.max.bytes', 65536);
    this.rotateBytes = limit(
      'beacon.security.evidence.file.max.bytes',
      10 * 1024 * 1024
    );
    this.backups = Math.min(
      20,
      limit('beacon.security.evidence.file.backups', 3)
    );
    this.ledger = new RuntimeLedger(this.identity, this.profile, this.output);
    this.sentRuns = new Map();

    this.securityQueue = [];
    this.sbomQueue = [];
    this.securityQueueSize = limit('beacon.security.export.queue.size', 1024);
    this.sbomQueueSize = limit('beacon.security.export.sbom.queue.size', 256);
    this.securityEventsPerSecond = limit(
      'beacon.security.export.security.events-per-second',
      100
    );
    this.securityBytesPerSecond = limit(
      'beacon.security.export.security.bytes-per-second',
      524288
    );
    this.sbomEventsPerSecond = limit(
      'beacon.security.export.sbom.events-per-second',
      200
    );
    this.sbomBytesPerSecond = limit(
      'beacon.security.export.sbom.bytes-per-second',
      262144
    );
    this.counters = Object.create(null);
    this.dropped = 0;
    this.droppedByChannel = { security: 0, sbom: 0 };
    this.pendingDropped = { security: 0, sbom: 0 };
    this.draining = { security: false, sbom: false };
    this.sbomResumeTimer = null;
    this.budget = {
      security: { second: 0, events: 0, bytes: 0 },
      sbom: { second: 0, events: 0, bytes: 0 },
    };
    this.lastFileWrite = 0;
    this.lastOtelCall = 0;
    this.lastError = 0;
    this.snapshotFailureLastEmitted = 0;
    this.accepting = true;
    this.closed = false;
    this.ticking = false;
    this.lastTickPromise = null;
    this.closePromise = null;
    this.workerFailed = null;
    this.ioRequests = new Map();
    this.ioSequence = 0;
    this.loggerPromise = null;
    this.apiPromise = null;
    this.explicitLogger = null;

    this.worker = null;
    try {
      this.worker = new Worker(new URL('./io-worker.mjs', import.meta.url), {
        type: 'module',
        execArgv: [],
      });
      this.worker.on('message', message => this._onIoMessage(message));
      this.worker.on('error', error => this._onIoFailure(error));
      this.worker.on('exit', code => {
        if (!this.closed && code !== 0)
          this._onIoFailure(new Error(`io_worker_exit:${code}`));
      });
      this.worker.unref();
    } catch (error) {
      this._onIoFailure(error);
    }

    this.initialization = this._ioRequest('initialize', {
      evidencePath: this.evidencePath,
      rotateBytes: this.rotateBytes,
      backups: this.backups,
    }).catch(error => {
      this._onIoFailure(error);
      return null;
    });
    this.monitor = setInterval(() => {
      void this._tick(false);
    }, 1000);
    this.monitor.unref?.();
    void this._tick(true);
  }

  emit(event, { evidence = false } = {}) {
    if (!isRecord(event)) {
      this._loss('beacon.security.invalid_event');
      return false;
    }
    const value = eventRecord(copy(event), this.identity);
    const channel =
      value.event_name === 'beacon.security.sbom.snapshot' ||
      asText(value.event_name).startsWith('beacon.security.sbom.')
        ? 'sbom'
        : 'security';
    if (!this.accepting) {
      this._loss(`${channel}.closed`, value);
      return false;
    }
    const queue = channel === 'security' ? this.securityQueue : this.sbomQueue;
    const maximum =
      channel === 'security' ? this.securityQueueSize : this.sbomQueueSize;
    if (queue.length >= maximum) {
      this._loss(`${channel}.queue_full`, value);
      return false;
    }
    queue.push({
      event: value,
      contextEvent: value,
      evidence: Boolean(evidence),
    });
    this._count(`${channel}.queued`);
    void this._drain(channel);
    return true;
  }

  delivery() {
    return {
      counters: { ...this.counters },
      dropped: this.dropped,
      security_dropped: this.droppedByChannel.security,
      sbom_dropped: this.droppedByChannel.sbom,
      security_queue_depth: this.securityQueue.length,
      sbom_queue_depth: this.sbomQueue.length,
      last_file_write_at: isoFromSeconds(this.lastFileWrite),
      last_otel_api_call_at: isoFromSeconds(this.lastOtelCall),
      evidence_file: this.evidencePath || 'disabled',
      otel_logs_config: text('otel.logs.exporter', 'agent_default'),
      backend_acknowledgement: 'unknown',
      otel_semantics: 'api_emit_is_not_export_or_backend_ack',
      delivery_guarantee: 'bounded_best_effort_no_agent_replay',
      file_write_semantics: 'flushed_not_fsynced',
    };
  }

  async close(timeoutMillis = 1500) {
    if (this.closePromise) return this.closePromise;
    this.closePromise = this._close(Math.max(0, Number(timeoutMillis) || 0));
    return this.closePromise;
  }

  async _close(timeoutMillis) {
    clearInterval(this.monitor);
    const deadline = Date.now() + timeoutMillis;
    const remaining = () => Math.max(0, deadline - Date.now());
    try {
      await withTimeout(this._tick(true), remaining());
    } catch (error) {
      this._diagnostic(error);
    }
    while (
      (this.securityQueue.length ||
        this.sbomQueue.length ||
        this.draining.security ||
        this.draining.sbom) &&
      Date.now() < deadline
    ) {
      await sleep(Math.min(10, Math.max(1, deadline - Date.now())));
    }
    this.accepting = false;
    clearTimeout(this.sbomResumeTimer);
    this.sbomResumeTimer = null;
    this._discardPending(this.securityQueue, 'security');
    this._discardPending(this.sbomQueue, 'sbom');
    try {
      await withTimeout(this._tick(true, { emitEvents: false }), remaining());
    } catch (error) {
      this._diagnostic(error);
    }
    this.closed = true;
    if (this.worker) {
      try {
        await this._ioRequest('close', {}, Math.max(1, remaining()));
      } catch {
        await this.worker.terminate().catch(() => {});
      }
    }
  }

  async _tick(force, { emitEvents = true } = {}) {
    if (this.ticking) {
      if (!force) return this.lastTickPromise;
      await this.lastTickPromise;
      return this._tick(force, { emitEvents });
    }
    this.ticking = true;
    this.lastTickPromise = (async () => {
      if (emitEvents) this._emitPendingLoss();
      let control = null;
      let controlAvailable = false;
      try {
        const response = await this._ioRequest('read-control', {
          path: this.controlPath,
        });
        if (response?.exists) {
          control = response.value;
          controlAvailable = true;
        }
      } catch (error) {
        this.ledger.controlFailure('unparsed', errorText(error));
      }
      const result = this.ledger.tick(this.delivery(), {
        control: controlAvailable ? control : null,
        force,
        emitEvents,
      });
      if (emitEvents)
        for (const event of result.events) this.emit(event, { evidence: true });
      if (this.localOutputEnabled) {
        for (const key of ['findings', 'runs']) {
          if (
            result[key] &&
            (await this._writeSnapshot(key + '.json', result[key], key))
          )
            this.ledger.writtenRevisions[key] = result.revisions[key];
        }
        if (result.health)
          await this._writeSnapshot('health.json', result.health);
      }
      return result;
    })()
      .catch(error => {
        this._diagnostic(error);
        return null;
      })
      .finally(() => {
        this.ticking = false;
      });
    return this.lastTickPromise;
  }

  async _writeSnapshot(name, value, key) {
    try {
      const path = join(this.output, name);
      if (key) {
        const { [key]: records, ...envelope } = value;
        await this._ioRequest('snapshot-begin', { path, key, envelope });
        // Reuse committed run rows in the worker; only changed rows cross threads.
        for (const record of records) {
          const cached =
            key === 'runs' && this.sentRuns.get(record.run_id) === record;
          await this._ioRequest(
            'snapshot-row',
            cached ? { runId: record.run_id } : { record }
          );
        }
        await this._ioRequest('snapshot-commit', {});
        if (key === 'runs')
          this.sentRuns = new Map(
            records.map(record => [record.run_id, record])
          );
      } else await this._ioRequest('write-json', { path, value });
      return true;
    } catch (error) {
      this.ledger.recordSnapshotFailure();
      const current = Date.now();
      if (
        current - this.snapshotFailureLastEmitted >= 30000 &&
        this.accepting
      ) {
        this.snapshotFailureLastEmitted = current;
        this.emit(
          {
            event_name: 'beacon.security.snapshot.failed',
            error_type: errorText(error),
            count: this.ledger.snapshotFailures,
          },
          { evidence: true }
        );
      }
      return false;
    }
  }

  async _drain(channel) {
    if (this.draining[channel] || (channel === 'sbom' && this.sbomResumeTimer))
      return;
    this.draining[channel] = true;
    const queue = channel === 'security' ? this.securityQueue : this.sbomQueue;
    const eventsLimit =
      channel === 'security'
        ? this.securityEventsPerSecond
        : this.sbomEventsPerSecond;
    const bytesLimit =
      channel === 'security'
        ? this.securityBytesPerSecond
        : this.sbomBytesPerSecond;
    try {
      while (queue.length > 0) {
        const entry = queue[0];
        let encoded;
        try {
          encoded = this._encodeRecord(entry.event);
        } catch (error) {
          queue.shift();
          throw error;
        }
        if (
          !this._withinBudget(
            channel,
            encoded.bytes.length,
            eventsLimit,
            bytesLimit,
            entry.event
          )
        ) {
          if (channel === 'sbom' && encoded.bytes.length <= bytesLimit) {
            this.sbomResumeTimer = setTimeout(
              () => {
                this.sbomResumeTimer = null;
                void this._drain('sbom');
              },
              Math.max(1, 1000 - (Date.now() % 1000))
            );
            this.sbomResumeTimer.unref();
            break;
          }
          queue.shift();
          continue;
        }
        queue.shift();
        const exported = { ...entry, event: encoded.event };
        if (encoded.truncated) {
          this._recordTruncation(entry.event, channel);
          if (channel === 'security' && !exported.evidence)
            exported.evidence = true;
        }
        await this._export(exported, encoded.bytes, channel);
        this._count(`${channel}.processed`);
        await Promise.resolve();
      }
    } catch (error) {
      this._count(`${channel}.failed`);
      this._recordDeliveryFailure(undefined, error);
      this._diagnostic(error);
    } finally {
      this.draining[channel] = false;
      if (queue.length > 0) void this._drain(channel);
    }
  }

  _encodeRecord(event) {
    // emit() already owns a detached copy. Encoding must not clone its graph again.
    const original = event;
    let encoded = encode(original);
    if (Buffer.byteLength(encoded) <= this.maxBytes)
      return {
        event: original,
        bytes: Buffer.from(encoded, 'utf8'),
        truncated: false,
      };
    const reduced = { ...original };
    for (const field of ['propagation', 'ranges', 'sources'])
      delete reduced[field];
    reduced.truncated = true;
    reduced.truncation_reason = 'record_byte_limit';
    encoded = encode(reduced);
    if (Buffer.byteLength(encoded) <= this.maxBytes)
      return {
        event: reduced,
        bytes: Buffer.from(encoded, 'utf8'),
        truncated: true,
      };
    const summary = {
      schema_version: 1,
      source: original.source,
      event_name: 'beacon.security.export.truncated',
      original_event: original.event_name,
      evidence_id: original.evidence_id ?? null,
      sbom_id: original.sbom_id ?? null,
      truncated: true,
    };
    encoded = encode(summary);
    if (Buffer.byteLength(encoded) <= this.maxBytes)
      return {
        event: summary,
        bytes: Buffer.from(encoded, 'utf8'),
        truncated: true,
      };
    const minimal = {
      schema_version: 1,
      source: original.source,
      event_name: 'beacon.security.export.truncated',
      truncated: true,
    };
    encoded = encode(minimal);
    if (Buffer.byteLength(encoded) > this.maxBytes) {
      this._count('record_too_small_for_envelope');
      throw new Error('record_limit');
    }
    return {
      event: minimal,
      bytes: Buffer.from(encoded, 'utf8'),
      truncated: true,
    };
  }

  _withinBudget(channel, bytes, eventsLimit, bytesLimit, event) {
    const state = this.budget[channel];
    const second = Math.floor(Date.now() / 1000);
    if (second !== state.second) {
      state.second = second;
      state.events = 0;
      state.bytes = 0;
    }
    const diagnostic = this._isLossDiagnostic(event);
    if (
      !diagnostic &&
      (state.events >= eventsLimit || state.bytes + bytes > bytesLimit)
    ) {
      if (channel === 'sbom' && bytes <= bytesLimit)
        this._count('sbom.budget_deferred');
      else this._loss(`${channel}.budget_exceeded`, event);
      return false;
    }
    if (!diagnostic) {
      state.events += 1;
      state.bytes += bytes;
    }
    return true;
  }

  async _export(entry, bytes, channel) {
    const event = entry.event;
    try {
      await this._emitOtel(bytes.toString('utf8'), event, entry.contextEvent);
      this.lastOtelCall = Date.now() / 1000;
      this._count(`${channel}.otel_api_emitted`);
    } catch (error) {
      this._count(`${channel}.otel_api_failed`);
      this._recordDeliveryFailure(event, error);
      this._diagnostic(error);
    }
    if (
      channel !== 'security' ||
      !this.evidencePath ||
      (!entry.evidence && !this._isDiagnostic(event))
    )
      return;
    try {
      await this._ioRequest('append-evidence', {
        line: bytes.toString('utf8'),
      });
      this.lastFileWrite = Date.now() / 1000;
      this._count('beacon.security.file_written');
    } catch (error) {
      this._count('beacon.security.file_failed');
      this._recordDeliveryFailure(event, error);
      this._diagnostic(error);
    }
  }

  async _emitOtel(body, event, contextEvent = event) {
    const logger = await this._getLogger();
    if (!logger || typeof logger.emit !== 'function')
      throw new Error('otel_logs_unavailable');
    const context = await this._otelContext(contextEvent);
    const logRecord = {
      // OTel JS Logs accepts a TimeInput in milliseconds and performs the
      // SDK-side conversion. Supplying nanoseconds here would multiply the
      // timestamp once more in SDK encoders.
      timestamp: Date.now(),
      body,
      severityText: 'INFO',
      severityNumber: 9,
      attributes: {
        'event.name': asText(event.event_name),
        source: event.source,
      },
      eventName: asText(event.event_name),
    };
    if (context !== undefined) logRecord.context = context;
    logger.emit(logRecord);
  }

  async _getLogger() {
    if (this.explicitLogger && typeof this.explicitLogger.emit === 'function')
      return this.explicitLogger;
    if (
      globalThis.__BEACON_SECURITY_LOGGER__ &&
      typeof globalThis.__BEACON_SECURITY_LOGGER__.emit === 'function'
    )
      return globalThis.__BEACON_SECURITY_LOGGER__;
    if (!this.loggerPromise) {
      this.loggerPromise = import('@opentelemetry/api-logs')
        .then(module => {
          const api = module.logs || module.default || module;
          const getLogger = api && api.getLogger;
          return typeof getLogger === 'function'
            ? getLogger.call(api, PRODUCT, VERSION)
            : null;
        })
        .catch(() => null);
    }
    return this.loggerPromise;
  }

  async _otelContext(event) {
    const traceId = asText(event.trace_id).toLowerCase();
    const spanId = asText(
      event.server_span_id || event.current_span_id
    ).toLowerCase();
    const valid =
      /^[0-9a-f]{32}$/.test(traceId) &&
      /^[0-9a-f]{16}$/.test(spanId) &&
      !/^0+$/.test(traceId) &&
      !/^0+$/.test(spanId);
    if (!this.apiPromise)
      this.apiPromise = import('@opentelemetry/api').catch(() => null);
    const module = await this.apiPromise;
    const api = module?.default || module;
    if (!api?.ROOT_CONTEXT || typeof api.trace?.setSpanContext !== 'function')
      return undefined;
    if (!valid) return api.ROOT_CONTEXT;
    const flags = Number(event.trace_flags);
    return api.trace.setSpanContext(api.ROOT_CONTEXT, {
      traceId,
      spanId,
      traceFlags: Number.isFinite(flags) ? flags & 0xff : 0,
      isRemote: false,
    });
  }

  _emitPendingLoss() {
    for (const channel of ['security', 'sbom']) {
      const amount = this.pendingDropped[channel];
      this.pendingDropped[channel] = 0;
      if (amount <= 0) continue;
      this.emit(
        {
          event_name:
            channel === 'security'
              ? 'beacon.security.export.dropped'
              : 'beacon.security.sbom.export.dropped',
          observed_at: new Date().toISOString(),
          count: amount,
          delivery: this.delivery(),
        },
        { evidence: true }
      );
    }
  }

  _discardPending(queue, channel) {
    if (!queue.length) return;
    const pending = queue.splice(0, queue.length);
    this._count(`${channel}.shutdown_pending`, pending.length);
    this.dropped += pending.length;
    this.droppedByChannel[channel] += pending.length;
    this.pendingDropped[channel] += pending.length;
    if (channel === 'security') {
      this.ledger.count('delivery_loss', pending.length);
      for (const entry of pending)
        this.ledger.recordDeliveryLoss(entry.event, 1);
    }
  }

  _loss(reason, event) {
    const channel = asText(reason).startsWith('sbom.') ? 'sbom' : 'security';
    this.dropped += 1;
    this.droppedByChannel[channel] += 1;
    this.pendingDropped[channel] += 1;
    this._count(reason);
    if (channel === 'security') {
      this.ledger.count('delivery_loss');
      this.ledger.recordDeliveryLoss(event, 1);
    }
  }

  _recordDeliveryFailure(event, _error) {
    if (
      event &&
      (event.event_name === 'beacon.security.sbom.snapshot' ||
        asText(event.event_name).startsWith('beacon.security.sbom.'))
    )
      return;
    this.ledger.count('delivery_failure');
    this.ledger.recordDeliveryLoss(event, 1);
  }

  _recordTruncation(event, channel) {
    this._count(`${channel}.record_truncated`);
    if (channel === 'security') {
      this.ledger.count('delivery_loss');
      this.ledger.recordDeliveryLoss(event, 1);
    }
  }

  _count(name, amount = 1) {
    const raw = asText(name);
    const key = raw.startsWith('security.')
      ? `beacon.${raw}`
      : raw.startsWith('sbom.')
        ? `beacon.security.${raw}`
        : raw;
    this.counters[key] = (this.counters[key] || 0) + (Number(amount) || 0);
  }

  _diagnostic(error) {
    const current = Date.now();
    if (current - this.lastError < 30000) return;
    this.lastError = current;
    try {
      console.error(`[Beacon Security] export failure: ${errorText(error)}`);
    } catch {
      // Diagnostics must not escape an application callback.
    }
  }

  _isDiagnostic(event) {
    const name = asText(event?.event_name);
    return (
      new Set([
        'beacon.security.collection.incomplete',
        'beacon.security.finding.summary',
        'beacon.security.snapshot.failed',
        'beacon.security.export.dropped',
        'beacon.security.sbom.export.dropped',
        'beacon.security.export.truncated',
      ]).has(name) || name.startsWith('beacon.security.instrumentation.')
    );
  }

  _isLossDiagnostic(event) {
    const name = asText(event?.event_name);
    return (
      name === 'beacon.security.export.dropped' ||
      name === 'beacon.security.sbom.export.dropped'
    );
  }

  _ioRequest(operation, value, timeoutMillis = 0) {
    if (!this.worker || this.workerFailed)
      return Promise.reject(
        this.workerFailed || new Error('io_worker_unavailable')
      );
    const id = ++this.ioSequence;
    return new Promise((resolve, reject) => {
      let timer;
      if (timeoutMillis > 0)
        timer = setTimeout(() => {
          this.ioRequests.delete(id);
          reject(new Error('io_worker_timeout'));
        }, timeoutMillis);
      this.ioRequests.set(id, {
        resolve: result => {
          if (timer) clearTimeout(timer);
          resolve(result);
        },
        reject: error => {
          if (timer) clearTimeout(timer);
          reject(error);
        },
      });
      try {
        this.worker.postMessage({ id, operation, value });
      } catch (error) {
        this.ioRequests.delete(id);
        if (timer) clearTimeout(timer);
        reject(error);
      }
    });
  }

  _onIoMessage(message) {
    const request = this.ioRequests.get(message?.id);
    if (!request) return;
    this.ioRequests.delete(message.id);
    if (message.ok) request.resolve(message.result);
    else request.reject(new Error(asText(message.error, 'io_worker_failure')));
  }

  _onIoFailure(error) {
    if (this.workerFailed) return;
    this.workerFailed =
      error instanceof Error ? error : new Error(errorText(error));
    this.ledger.controlFailure('unparsed', errorText(this.workerFailed));
    for (const request of this.ioRequests.values())
      request.reject(this.workerFailed);
    this.ioRequests.clear();
  }
}

export { RuntimeLedger };
export default Exporter;
