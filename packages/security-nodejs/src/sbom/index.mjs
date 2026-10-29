import { eventRecord, onlineEvent, componentReference } from '../schema.mjs';
import { Worker } from 'node:worker_threads';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

import { text, flag, limit, digest, VERSION } from '../config.mjs';

const DEFAULTS = Object.freeze({
  components: 10000,
  entries: 100000,
  archiveBytes: 64 * 1024 * 1024,
  scanBytes: 512 * 1024 * 1024,
  cacheSeconds: 300,
  refreshSeconds: 300,
});

const MAX_INPUT = 4096;
const MAX_IDENTITY_VALUE = 1024;
const MAX_OBSERVATIONS = 4096;
const OBSERVATION_BATCH = 64;
const OBSERVATION_IN_FLIGHT = 2;

function bounded(value, maximum = MAX_INPUT) {
  if (value === undefined || value === null) return '';
  try {
    return String(value).slice(0, maximum);
  } catch {
    return '';
  }
}

function configuredText(key, fallback = '') {
  try {
    const value = text(key);
    return value === undefined || value === null
      ? fallback
      : bounded(value, MAX_INPUT);
  } catch {
    return fallback;
  }
}

function configuredFlag(key, fallback = true) {
  try {
    return Boolean(flag(key, fallback));
  } catch {
    return fallback;
  }
}

function configuredLimit(key, fallback) {
  try {
    const value = Number(limit(key, fallback));
    return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
  } catch {
    return fallback;
  }
}

function absoluteOutputPath(output) {
  const configured = configuredText('beacon.security.sbom.output', '');
  const supplied =
    output === undefined || output === null ? '' : bounded(output, MAX_INPUT);
  const candidate =
    configured ||
    supplied ||
    path.join(process.cwd(), 'beacon-security-output');
  const absolute = path.resolve(candidate);
  // Both a directory and an explicitly configured JSON file are accepted. The
  // The worker receives one concrete local snapshot path when enabled.
  if (absolute.toLowerCase().endsWith('.json')) return absolute;
  return path.join(absolute, 'application.cdx.json');
}

function identityValue(value) {
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return bounded(value, MAX_IDENTITY_VALUE);
  }
  return '';
}

function boundedObject(value, depth = 0) {
  if (depth > 4 || value === null || value === undefined) return {};
  if (Array.isArray(value))
    return value.slice(0, 64).map(item => boundedObject(item, depth + 1));
  if (typeof value !== 'object') return identityValue(value);
  const result = {};
  for (const key of Object.keys(value).slice(0, 128)) {
    const boundedKey = bounded(key, 256);
    const item = value[key];
    if (item && typeof item === 'object')
      result[boundedKey] = boundedObject(item, depth + 1);
    else if (
      typeof item === 'string' ||
      typeof item === 'number' ||
      typeof item === 'boolean'
    ) {
      result[boundedKey] = identityValue(item);
    }
  }
  return result;
}

function normalizeIdentity(input) {
  const source = input && typeof input === 'object' ? input : {};
  const service = boundedObject(source.service);
  const code = boundedObject(source.code);
  const runtime = boundedObject(source.runtime);
  const applicationId = bounded(
    source.application_id ?? source.applicationId,
    MAX_IDENTITY_VALUE
  );
  const instanceId =
    bounded(source.instance_id ?? source.instanceId, MAX_IDENTITY_VALUE) ||
    randomUUID();
  const identityStatus =
    bounded(source.identity_status ?? source.identityStatus, 128) ||
    'incomplete';
  const fallbackName =
    bounded(service['service.name'] ?? service.name, MAX_IDENTITY_VALUE) ||
    'unknown-node-application';
  const namespace = bounded(
    service['service.namespace'] ?? service.namespace,
    MAX_IDENTITY_VALUE
  );
  let stableApplicationId = applicationId;
  if (!stableApplicationId) {
    // digest is the configured root helper. This is identity material, never a
    // digest of an installed artifact and therefore safe to calculate here.
    stableApplicationId = `app-${bounded(digest(`${namespace}|${fallbackName}`), 128)}`;
  }
  return {
    application_id: stableApplicationId,
    instance_id: instanceId,
    service,
    code,
    runtime,
    identity_status: identityStatus,
  };
}

function includeRoots() {
  const configured = configuredText('beacon.security.node.include', '');
  const values = configured
    .split(',')
    .map(item => item.trim())
    .filter(Boolean)
    .slice(0, 256);
  // An empty include is useful for applications that do not configure an
  // include explicitly: the worker can still produce the package root SBOM.
  return values.length ? values : [process.cwd()];
}

function lookupPath(value) {
  const raw = bounded(value, MAX_INPUT).trim();
  if (!raw) return { path: '', url: '', query: '', reason: 'empty_filename' };
  try {
    const url = new URL(raw);
    if (url.protocol !== 'file:')
      return {
        path: '',
        url: url.href,
        query: url.search,
        reason: 'unsupported_url_scheme',
      };
    return {
      path: path.resolve(fileURLToPath(url)),
      url: url.href,
      query: url.search,
    };
  } catch {
    // A loader normally supplies file URLs, but accepting a plain path keeps
    // resolve useful for integrations that pass the filename from a hook.
    if (/^[a-zA-Z][a-zA-Z+.-]*:/.test(raw))
      return { path: '', url: raw, query: '', reason: 'invalid_file_url' };
    return {
      path: path.resolve(raw),
      url: pathToFileURL(path.resolve(raw)).href,
      query: '',
    };
  }
}

function withinPath(filename, root) {
  const file = path.resolve(filename);
  const base = path.resolve(root);
  return file === base || file.startsWith(`${base}${path.sep}`);
}

function clone(value) {
  if (typeof structuredClone === 'function') return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}

function emitSafely(callback, event) {
  if (typeof callback !== 'function') return;
  try {
    callback(event);
  } catch {
    // An exporter is outside the snapshot publication contract.
  }
}

/**
 * Background Node runtime SBOM inventory.
 *
 * The published mapping is replaced only after a successful collection and
 * optional local CycloneDX write. resolve() never touches disk or asks the
 * worker to scan; it only consults that immutable mapping.
 */
export class SbomInventory {
  constructor(identity = {}, output, onEvent) {
    this.identity = normalizeIdentity(identity);
    this.output = absoluteOutputPath(output);
    this.onEvent = event => {
      const projected = onlineEvent(eventRecord(event, this.identity));
      if (projected) emitSafely(onEvent, projected);
    };
    this.enabled = configuredFlag('beacon.security.sbom.enabled', true);
    this.settings = Object.freeze({
      maxComponents: configuredLimit(
        'beacon.security.sbom.max.components',
        DEFAULTS.components
      ),
      maxEntries: configuredLimit(
        'beacon.security.sbom.max.entries',
        DEFAULTS.entries
      ),
      maxArchiveBytes: configuredLimit(
        'beacon.security.sbom.max.archive.bytes',
        DEFAULTS.archiveBytes
      ),
      maxScanBytes: configuredLimit(
        'beacon.security.sbom.max.scan.bytes',
        DEFAULTS.scanBytes
      ),
      cacheSeconds: configuredLimit(
        'beacon.security.sbom.cache.seconds',
        DEFAULTS.cacheSeconds
      ),
      refreshSeconds: configuredLimit(
        'beacon.security.sbom.refresh.seconds',
        DEFAULTS.refreshSeconds
      ),
      maxQueue: Math.max(
        1,
        Math.min(
          MAX_OBSERVATIONS,
          configuredLimit('beacon.security.sbom.max.entries', DEFAULTS.entries)
        )
      ),
    });
    this.buildFile = configuredText('beacon.security.sbom.build.file', '');
    this.worker = null;
    this.started = false;
    this.closed = false;
    this.pendingObservations = [];
    this.observationInFlight = 0;
    this.droppedObservations = 0;
    this.workerFailureReported = false;
    this.pendingClose = null;
    this.published = Object.freeze({
      byPath: Object.freeze(Object.create(null)),
      byUrl: Object.freeze(Object.create(null)),
      byPackageRoot: Object.freeze(Object.create(null)),
      components: Object.freeze(Object.create(null)),
      applicationRoots: Object.freeze([]),
    });
  }

  start() {
    if (this.started || this.closed || !this.enabled) return;
    this.started = true;
    this.workerFailureReported = false;
    try {
      const workerUrl = new URL('./worker.mjs', import.meta.url);
      this.worker = new Worker(workerUrl, {
        type: 'module',
        execArgv: [],
        workerData: {
          identity: clone(this.identity),
          output: this.output,
          include: includeRoots(),
          buildFile: this.buildFile,
          version: bounded(VERSION, 128),
          settings: this.settings,
          localOutputEnabled: configuredFlag(
            'beacon.security.local-output.enabled',
            false
          ),
        },
      });
      this.worker.on('message', message => this.#onWorkerMessage(message));
      this.worker.on('error', error => this.#onWorkerFailure(error));
      this.worker.on('exit', code => {
        if (this.pendingClose) {
          this.pendingClose.resolve();
          this.pendingClose = null;
        } else if (code !== 0 && !this.closed) {
          this.#onWorkerFailure(
            new Error(`SBOM worker exited with code ${code}`)
          );
        }
      });
      this.#drainObservations();
      this.worker.postMessage({ type: 'refresh' });
      // Install all listeners before dropping the worker's event-loop ref.
      // Adding a MessagePort listener after unref() refs it again in Node,
      // which would keep an otherwise idle application alive indefinitely.
      this.worker.unref();
    } catch (error) {
      this.#onWorkerFailure(error);
    }
  }

  /** Observe one loader URL. The worker validates and maps only real files. */
  observe(url) {
    if (this.closed || !this.enabled) return false;
    let value;
    try {
      value = bounded(url instanceof URL ? url.href : url, MAX_INPUT);
    } catch {
      value = '';
    }
    if (!value) return false;
    let dropped = false;
    if (this.pendingObservations.length >= this.settings.maxQueue) {
      this.pendingObservations.shift();
      dropped = true;
      this.droppedObservations += 1;
    }
    this.pendingObservations.push(value);
    this.#drainObservations();
    return true;
  }

  /** Resolve only against the last fully published worker snapshot. */
  resolve(filename) {
    const snapshot = this.published;
    const lookup = lookupPath(filename);
    if (lookup.reason) return null;
    const match = snapshot.byUrl[lookup.url] || snapshot.byPath[lookup.path];
    if (!match) {
      let parent = lookup.path;
      for (let depth = 0; depth < 64; depth++) {
        const ref = snapshot.byPackageRoot?.[parent];
        if (ref) return componentReference(snapshot.components[ref]);
        const next = path.dirname(parent);
        if (next === parent) break;
        parent = next;
      }
      const applicationRoot = snapshot.applicationRoots.find(root =>
        withinPath(lookup.path, root)
      );
      if (applicationRoot) {
        const service = this.identity.service || {};
        return componentReference({
          name: service['service.name'] || service.name,
          version: service['service.version'] || service.version,
        });
      }
      return null;
    }
    // Keep the event component bounded and privacy-safe. The worker's
    // absolute source path is only an internal lookup key; a caller receives
    // the stable component reference and the observed URL query semantics.
    if (match['bom-ref'] === this.identity.application_id) {
      const service = this.identity.service || {};
      return componentReference({
        name: service['service.name'] || service.name,
        version: service['service.version'] || service.version,
      });
    }
    return componentReference(snapshot.components[match['bom-ref']]);
  }

  async close(timeoutMillis = 1500) {
    this.closed = true;
    const worker = this.worker;
    this.worker = null;
    this.pendingObservations = [];
    if (!worker) return;
    const timeout = Number.isFinite(Number(timeoutMillis))
      ? Math.max(0, Number(timeoutMillis))
      : 1500;
    await new Promise(resolve => {
      let settled = false;
      let timer;
      const finish = () => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (this.pendingClose) this.pendingClose = null;
        resolve();
      };
      this.pendingClose = { resolve: finish, worker };
      try {
        worker.postMessage({ type: 'close' });
      } catch {
        finish();
        return;
      }
      timer = setTimeout(() => {
        worker
          .terminate()
          .catch(() => undefined)
          .finally(finish);
      }, timeout);
    });
  }

  #drainObservations() {
    if (!this.worker || this.closed) return;
    while (
      this.observationInFlight < OBSERVATION_IN_FLIGHT &&
      this.pendingObservations.length
    ) {
      const values = this.pendingObservations.splice(0, OBSERVATION_BATCH);
      try {
        this.worker.postMessage({ type: 'observe_batch', values });
        this.observationInFlight += 1;
      } catch {
        this.pendingObservations.unshift(...values);
        this.#onWorkerFailure(new Error('SBOM observation queue unavailable'));
        return;
      }
    }
  }

  #onWorkerMessage(message) {
    if (!message || typeof message !== 'object') return;
    if (message.type === 'closed') {
      const pending = this.pendingClose;
      if (pending) {
        this.pendingClose = null;
        pending.resolve();
        pending.worker.terminate().catch(() => undefined);
      }
      return;
    }
    if (message.type === 'observe_ack') {
      this.observationInFlight = Math.max(0, this.observationInFlight - 1);
      if (Number(message.dropped) > 0) {
        this.droppedObservations += Number(message.dropped);
      }
      this.#drainObservations();
      return;
    }
    if (message.type === 'published') {
      const snapshot = message.snapshot || {};
      const byPath = Object.freeze({ ...(snapshot.byPath || {}) });
      const byUrl = Object.freeze({ ...(snapshot.byUrl || {}) });
      const byPackageRoot = Object.freeze({
        ...(snapshot.byPackageRoot || {}),
      });
      const applicationRoots = Object.freeze(
        Array.isArray(snapshot.application_roots)
          ? snapshot.application_roots
              .slice(0, 256)
              .map(root => bounded(root, MAX_INPUT))
              .filter(Boolean)
          : []
      );
      this.published = Object.freeze({
        byPath,
        byUrl,
        byPackageRoot,
        components: Object.freeze({ ...(snapshot.components || {}) }),
        applicationRoots,
      });
      for (const event of Array.isArray(message.events) ? message.events : [])
        emitSafely(this.onEvent, event);
      return;
    }
    if (message.type === 'event') {
      // Collection failures do not replace the last successful inventory.
    }
    if (message.type === 'failure')
      this.lastFailure = bounded(message.error, 256);
  }

  #onWorkerFailure(error) {
    if (this.closed || this.workerFailureReported) return;
    this.workerFailureReported = true;
    this.worker = null;
    this.observationInFlight = 0;
    this.lastFailure = bounded(error?.name || 'WorkerError', 256);
  }
}

export default SbomInventory;
