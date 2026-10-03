import module from 'node:module';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isMainThread } from 'node:worker_threads';
import {
  register as registerIitm,
  supportsSyncHooks,
} from 'import-in-the-middle/register-hooks.mjs';
import {
  collectionConfigured,
  included,
  supportedRuntime,
  loaderCompatibility,
  digest,
} from './config.mjs';
import {
  start,
  getRuntime,
  startupGap,
  shutdown,
  mapSourceFile,
} from './core/runtime.mjs';
import * as values from './core/values.mjs';
import * as operations from './core/operations.mjs';
import * as calls from './core/calls.mjs';
import { transform } from './transform/index.mjs';

let installed = false,
  compatible = true;
let businessHook, iitmHook;
const cache = new Map();
let cacheBytes = 0;
const MAX_SOURCE_BYTES = 2 * 1024 * 1024,
  MAX_CACHE_BYTES = 16 * 1024 * 1024;
const legacy = value =>
  typeof value === 'string' &&
  /(?:import-in-the-middle|@opentelemetry\/instrumentation)\/(?:[^\s]*\/)?hook\.mjs(?:[\s"']|$)/.test(
    value
  );
function disableTransform(reason) {
  compatible = false;
  loaderCompatibility(false);
  startupGap(reason);
  businessHook?.deregister();
  iitmHook?.deregister();
}
function observeLegacyRegistration() {
  const original = module.register;
  module.register = function (specifier, ...args) {
    const value =
      typeof specifier === 'string'
        ? specifier
        : specifier instanceof URL
          ? specifier.href
          : '';
    if (legacy(value)) disableTransform('asynchronous_iitm_loader_conflict');
    return Reflect.apply(original, this, [specifier, ...args]);
  };
  module.syncBuiltinESMExports();
}
function sourceMap(source, filename) {
  const match = [
    ...source.matchAll(/(?:\/\/#|\/\*#)\s*sourceMappingURL=([^\s*]+)/g),
  ].at(-1);
  if (!match) return undefined;
  try {
    let content;
    if (match[1].startsWith('data:application/json')) {
      const comma = match[1].indexOf(',');
      content = match[1].slice(0, comma).endsWith(';base64')
        ? Buffer.from(match[1].slice(comma + 1), 'base64').toString()
        : decodeURIComponent(match[1].slice(comma + 1));
    } else {
      const url = new URL(match[1], pathToFileURL(filename));
      if (url.protocol !== 'file:' || statSync(url).size > MAX_SOURCE_BYTES)
        throw new Error('unavailable map');
      content = readFileSync(url, 'utf8');
    }
    if (Buffer.byteLength(content) > MAX_SOURCE_BYTES)
      throw new Error('large map');
    return JSON.parse(content);
  } catch {
    startupGap('source_map_unavailable');
    return undefined;
  }
}
function load(url, context, nextLoad) {
  const result = nextLoad(url, context);
  if (url.startsWith('file:')) getRuntime()?.inventory?.observe(url);
  if (
    !compatible ||
    !collectionConfigured() ||
    !included(url) ||
    !['module', 'commonjs'].includes(result.format)
  )
    return result;
  if (!/\.(?:c|m)?js$/.test(new URL(url).pathname)) return result;
  try {
    const filename = fileURLToPath(url);
    if (result.source == null && statSync(filename).size > MAX_SOURCE_BYTES) {
      startupGap('transform_source_limit');
      return result;
    }
    const source =
      result.source == null
        ? readFileSync(filename, 'utf8')
        : typeof result.source === 'string'
          ? result.source
          : Buffer.from(result.source).toString('utf8');
    if (Buffer.byteLength(source) > MAX_SOURCE_BYTES) {
      startupGap('transform_source_limit');
      return result;
    }
    const map = sourceMap(source, filename);
    const key =
      url +
      '\0' +
      result.format +
      '\0' +
      digest(source + (map ? JSON.stringify(map) : ''));
    let entry = cache.get(key);
    if (entry) {
      cache.delete(key);
      cache.set(key, entry);
    } else {
      const transformed = transform(source, filename, url, map, result.format);
      for (const reason of transformed.gaps || []) startupGap(reason);
      for (const original of transformed.sourceFiles)
        mapSourceFile(original, filename);
      for (const fn of transformed.exportedFunctions)
        calls.declareFunctionExport(url, fn.name, fn.id);
      entry = {
        code: transformed.code,
        bytes: Buffer.byteLength(transformed.code),
      };
      if (entry.bytes <= MAX_CACHE_BYTES) {
        while (
          cacheBytes + entry.bytes > MAX_CACHE_BYTES ||
          cache.size >= 256
        ) {
          const first = cache.keys().next().value;
          cacheBytes -= cache.get(first).bytes;
          cache.delete(first);
        }
        cache.set(key, entry);
        cacheBytes += entry.bytes;
      }
      getRuntime()?.exporter.ledger.count(
        transformed.gaps?.length ? 'unmodeled_modules' : 'transformed_modules'
      );
    }
    return { ...result, source: entry.code };
  } catch (error) {
    startupGap('transform_failed:' + (error?.name || 'Error'));
    getRuntime()?.exporter.ledger.count('transform_failures');
    return result;
  }
}
export function install() {
  if (installed || !isMainThread) return;
  installed = true;
  start(['express@4,5', 'fastify@5', 'pg@8', 'mysql2@3', 'undici@8']);
  if (!supportedRuntime() || !supportsSyncHooks()) {
    disableTransform('unsupported_runtime');
    return;
  }
  if (
    legacy(process.execArgv.join(' ')) ||
    legacy(process.env.NODE_OPTIONS || '')
  ) {
    disableTransform('asynchronous_iitm_loader_conflict');
    return;
  }
  Object.defineProperty(globalThis, Symbol.for('beacon.security.helpers.v1'), {
    value: Object.freeze({ ...values, ...operations, ...calls }),
    configurable: false,
  });
  const originalRegisterHooks = module.registerHooks;
  module.registerHooks = options => {
    const hooks = originalRegisterHooks(options);
    iitmHook = hooks;
    return hooks;
  };
  module.syncBuiltinESMExports();
  try {
    registerIitm({ shouldInclude: url => !included(url) });
  } finally {
    module.registerHooks = originalRegisterHooks;
    module.syncBuiltinESMExports();
  }
  businessHook = module.registerHooks({
    resolve(specifier, context, nextResolve) {
      const result = nextResolve(specifier, context);
      calls.resolveModule(context.parentURL || '', specifier, result.url);
      return result;
    },
    load,
  });
  observeLegacyRegistration();
  process.once('beforeExit', () => {
    void shutdown();
  });
}
