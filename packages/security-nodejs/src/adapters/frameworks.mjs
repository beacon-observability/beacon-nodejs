import { begin, bind, end, startupGap } from '../core/runtime.mjs';
import { isObject, sourceAccessor } from '../core/values.mjs';
import { model } from '../core/calls.mjs';
import { IncomingMessage } from 'node:http';
import { types } from 'node:util';

const PATCHED = Symbol.for('beacon.security.framework.handle.v1');
const WRAPPED = Symbol.for('beacon.security.framework.factory.v1');
const FASTIFY_STATE = Symbol.for('beacon.security.framework.fastify-state.v1');
const expressAccessorStates = new WeakMap();
const expressHeaderModels = new WeakSet();
const nativeHeadersGetter = Object.getOwnPropertyDescriptor(
  IncomingMessage.prototype,
  'headers'
)?.get;

const expressVersions = new Set([4, 5]);
const fastifyVersions = new Set([5]);

function text(value) {
  return value === undefined || value === null ? '' : String(value);
}

function versionMajor(version) {
  const match = /^\s*(\d+)/.exec(text(version));
  return match ? Number(match[1]) : 0;
}

function normalizedName(name) {
  const value = text(name).toLowerCase();
  if (value.includes('express')) return 'express';
  if (value.includes('fastify')) return 'fastify';
  return value;
}

function errorType(error) {
  try {
    return text(error?.constructor?.name || error?.name || 'Error').slice(
      0,
      128
    );
  } catch {
    return 'Error';
  }
}

function metadata(request) {
  const method = request?.method;
  return typeof method === 'string' ? { method } : {};
}

function captureValue(state, value, type, name, location) {
  if (!state || state.closed || !state.collection_enabled) return undefined;
  try {
    const marks = state.capture(value, type, name, location) || [];
    // Object capture records marks on fields. Returning an empty array here
    // would make values.get discard marks already attached to the receiver.
    return marks.length ? marks : undefined;
  } catch {
    state.gap('framework_source_capture_failed');
    return undefined;
  }
}

function captureFastifyCarrier(
  state,
  value,
  type,
  name,
  location,
  depth = 0,
  seen = new Set()
) {
  if (!isObject(value) || Buffer.isBuffer(value))
    return state.source(value, type, name, location);
  if (depth >= 6 || seen.size >= 512) {
    state.gap('fastify_source_traversal_limit');
    return [];
  }
  if (seen.has(value)) return [];
  if (types.isProxy(value)) {
    state.gap('fastify_source_proxy_object');
    return [];
  }
  seen.add(value);
  try {
    const keys = Object.keys(value);
    let count = 0;
    for (const key of keys) {
      if (++count > 128) {
        state.gap('fastify_source_field_limit');
        break;
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor.enumerable) continue;
      if (!('value' in descriptor)) {
        state.gap('fastify_source_accessor');
        continue;
      }
      state.putField(
        value,
        key,
        captureFastifyCarrier(
          state,
          descriptor.value,
          type,
          name ? `${name}.${key}` : key,
          location,
          depth + 1,
          seen
        )
      );
    }
  } catch {
    state.gap('fastify_source_capture_failed');
  }
  return [];
}

const capturedObjects = new WeakMap();

function captureAccessorValue(
  state,
  value,
  accessorKey,
  type,
  name,
  location,
  carrierKey,
  dedupeObject
) {
  if (carrierKey) {
    const carrier = validationCarriers.get(state)?.get(carrierKey);
    if (carrier?.sealed) return undefined;
  }
  if (dedupeObject && isObject(value)) {
    let keys = capturedObjects.get(state);
    if (!keys) {
      keys = new Map();
      capturedObjects.set(state, keys);
    }
    let seen = keys.get(accessorKey);
    if (!seen) {
      seen = new WeakSet();
      keys.set(accessorKey, seen);
    }
    if (seen.has(value)) return undefined;
    seen.add(value);
  }
  return captureValue(state, value, type, name, location);
}

function registerAccessor(
  state,
  object,
  key,
  type,
  name,
  fallbackLocation,
  carrierKey,
  dedupeObject = false
) {
  if (!state || !isObject(object)) return;
  try {
    sourceAccessor(object, key, (active, value, location) =>
      captureAccessorValue(
        active,
        value,
        key,
        type,
        name,
        location || fallbackLocation,
        carrierKey,
        dedupeObject
      )
    );
  } catch {
    state.gap('framework_accessor_registration_failed');
  }
}

function dataProperty(object, key) {
  for (
    let current = object;
    current;
    current = Object.getPrototypeOf(current)
  ) {
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (!descriptor) continue;
    return 'value' in descriptor ? descriptor.value : undefined;
  }
  return undefined;
}

function headersCarrier(request) {
  if (!request) return undefined;
  try {
    for (
      let current = request;
      current;
      current = Object.getPrototypeOf(current)
    ) {
      const descriptor = Object.getOwnPropertyDescriptor(current, 'headers');
      if (!descriptor) continue;
      if ('value' in descriptor) return descriptor.value;
      if (
        descriptor.get !== nativeHeadersGetter ||
        typeof nativeHeadersGetter !== 'function'
      )
        return undefined;
      return nativeHeadersGetter.call(request);
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function modelExpressHeaderMethod(method) {
  if (typeof method !== 'function' || expressHeaderModels.has(method)) return;
  expressHeaderModels.add(method);
  model(method, {
    after(_value, args, receiver, _location, state) {
      const request = receiver?.v;
      const header = args?.[0]?.v;
      if (
        !state ||
        !request ||
        (typeof header !== 'string' && typeof header !== 'number')
      )
        return [];
      const headers = headersCarrier(request);
      if (!isObject(headers)) {
        state.gap('express_header_method_carrier_unavailable');
        return [];
      }
      let key = String(header).toLowerCase();
      if (key === 'referrer') key = 'referer';
      return state.field(headers, key);
    },
  });
}

function installExpressHeaderMethods(candidate) {
  const request = dataProperty(candidate, 'request');
  if (!request) return;
  for (const name of ['get', 'header']) {
    try {
      modelExpressHeaderMethod(dataProperty(request, name));
    } catch {
      /* method modeling is best effort */
    }
  }
}

function safeBegin(request, response, requestMetadata) {
  try {
    return begin(request, response, requestMetadata);
  } catch {
    startupGap('framework_request_begin_failed');
    return undefined;
  }
}

function installExpressRequest(request, state) {
  if (!state || !request || !state.collection_enabled) return;
  // app.handle and nested Router.handle both run for one request. Do not
  // reinstall accessors after values.set has deliberately removed one.
  if (expressAccessorStates.get(request) === state) return;
  expressAccessorStates.set(request, state);
  registerAccessor(
    state,
    request,
    'headers',
    'http.request.header',
    'header',
    'express.request.headers',
    undefined,
    true
  );
  registerAccessor(
    state,
    request,
    'query',
    'http.request.parameter',
    'query',
    'express.request.query',
    undefined,
    true
  );
  registerAccessor(
    state,
    request,
    'params',
    'http.request.path',
    'path',
    'express.request.params',
    undefined,
    true
  );
  registerAccessor(
    state,
    request,
    'body',
    'http.request.body',
    'body',
    'express.request.body',
    undefined,
    true
  );

  // IncomingMessage.headers is an already materialized field. Reading it once
  // here captures headers even when the application never reads req.headers;
  // query, params and body remain lazy so this adapter never consumes input.
  try {
    const headers = headersCarrier(request);
    if (isObject(headers)) {
      captureAccessorValue(
        state,
        headers,
        'headers',
        'http.request.header',
        'header',
        'express.request.headers',
        undefined,
        true
      );
    } else state.gap('express_headers_capture_failed');
  } catch {
    state.gap('express_headers_capture_failed');
  }
}

function expressHandle(original) {
  if (typeof original !== 'function') return original;
  if (original[PATCHED]) return original;
  const wrapped = function frameworkHandle(...args) {
    const request = args[0];
    const response = args[1];
    const state = safeBegin(request, response, metadata(request));
    if (!state) return Reflect.apply(original, this, args);
    installExpressRequest(request, state);
    const invoke = () => Reflect.apply(original, this, args);
    try {
      return bind(state, invoke);
    } catch (error) {
      state.request.error_type = errorType(error);
      try {
        end(state);
      } catch {
        state.gap('framework_request_end_failed');
      }
      throw error;
    }
  };
  markWrapped(wrapped, original, PATCHED);
  return wrapped;
}

function patchMethod(target, key, wrapper) {
  if (!target || typeof target[key] !== 'function') return false;
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  const original = descriptor?.value || target[key];
  if (typeof original !== 'function') return false;
  if (original[PATCHED]) return true;
  const replacement = wrapper(original);
  if (replacement === original) return true;
  try {
    if (descriptor && descriptor.writable === false) return false;
    if (descriptor)
      Object.defineProperty(target, key, { ...descriptor, value: replacement });
    else target[key] = replacement;
    return true;
  } catch {
    return false;
  }
}

function markWrapped(wrapper, original, marker) {
  try {
    Object.defineProperty(wrapper, marker, { value: true });
    Object.defineProperty(wrapper, '__original', {
      value: original,
      configurable: true,
    });
    try {
      Object.defineProperty(wrapper, 'length', { value: original.length });
    } catch {
      /* function length is advisory */
    }
    try {
      Object.defineProperty(wrapper, 'name', {
        value: original.name,
        configurable: true,
      });
    } catch {
      /* function name is advisory */
    }
  } catch {
    // A wrapper remains safe if a host function rejects metadata properties.
  }
}

function expressCandidates(exports) {
  const values = [];
  if (typeof exports === 'function' || exports) values.push(exports);
  if (exports && typeof exports.default === 'function')
    values.push(exports.default);
  if (exports && exports.default && typeof exports.default === 'object')
    values.push(exports.default);
  return [...new Set(values)];
}

function installExpress(exports) {
  let patched = false;
  for (const candidate of expressCandidates(exports)) {
    installExpressHeaderMethods(candidate);
    const applicationPatched = patchMethod(
      candidate.application,
      'handle',
      expressHandle
    );
    const routerTargets = [
      candidate.Router,
      candidate.Router?.prototype,
    ].filter(Boolean);
    let routerPatched = false;
    for (const target of new Set(routerTargets))
      routerPatched =
        patchMethod(target, 'handle', expressHandle) || routerPatched;
    patched = patched || applicationPatched || routerPatched;
  }
  if (!patched) startupGap('express_handle_shape_unsupported');
  return exports;
}

function plainContainer(value) {
  if (!isObject(value) || Buffer.isBuffer(value)) return false;
  if (Array.isArray(value)) return true;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function snapshotCarrier(
  state,
  value,
  result = [],
  seen = new Set(),
  depth = 0,
  allowCustomPrototype = false
) {
  if (types.isProxy(value)) {
    state.gap('fastify_validation_snapshot_proxy');
    return result;
  }
  if ((!plainContainer(value) && !allowCustomPrototype) || seen.has(value))
    return result;
  if (depth >= 6 || seen.size >= 512) {
    state.gap('fastify_validation_snapshot_limit');
    return result;
  }
  seen.add(value);
  const fields = new Map();
  try {
    const keys = Object.keys(value);
    let count = 0;
    for (const key of keys) {
      if (++count > 128) {
        state.gap('fastify_validation_snapshot_field_limit');
        break;
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor.enumerable) continue;
      if (!('value' in descriptor)) {
        state.gap('fastify_validation_snapshot_accessor');
        continue;
      }
      fields.set(key, {
        before: descriptor.value,
        marks: state.field(value, key),
      });
      snapshotCarrier(state, descriptor.value, result, seen, depth + 1);
    }
  } catch {
    state.gap('fastify_validation_snapshot_failed');
  }
  result.push({ object: value, fields });
  return result;
}

function rememberCarrier(
  state,
  key,
  value,
  type,
  name,
  location,
  owner,
  capture = true
) {
  if (!state || !state.collection_enabled) return;
  let carriers = validationCarriers.get(state);
  if (!carriers) {
    carriers = new Map();
    validationCarriers.set(state, carriers);
  }
  const previous = carriers.get(key);
  if (value === undefined || value === null) {
    carriers.set(key, {
      root: value,
      objects: [],
      missing: true,
      sealed: false,
      blocked: false,
    });
    return;
  }
  if (!capture) {
    // Fastify creates query/params before onRequest. At preValidation their
    // current fields are the post-user-mutation view; re-capturing here would
    // re-taint a field that an instrumented assignment intentionally cleared.
    if (previous && previous.root !== value)
      state.gap(`fastify.${key}_validation_boundary`);
    carriers.set(key, {
      root: value,
      marks: owner && isObject(value) ? state.field(owner, key) : [],
      owner,
      objects: snapshotCarrier(state, value, [], new Set(), 0, key === 'query'),
      missing: false,
      sealed: false,
      blocked: false,
    });
    return;
  }
  const marks = captureFastifyCarrier(state, value, type, name, location);
  if (marks?.length && owner && isObject(owner)) {
    state.putField(owner, key, marks);
    if (Buffer.isBuffer(value)) state.put(value, marks);
  }
  carriers.set(key, {
    root: value,
    marks: marks || [],
    owner,
    objects: snapshotCarrier(state, value, [], new Set(), 0, key === 'query'),
    missing: false,
    sealed: false,
    blocked: false,
  });
}

function scalar(value) {
  return (
    value === null ||
    Buffer.isBuffer(value) ||
    ['string', 'number', 'boolean', 'bigint'].includes(typeof value)
  );
}

function reconcileCarrier(state, key, value, location) {
  const carriers = validationCarriers.get(state);
  const snapshot = carriers?.get(key);
  if (!snapshot) return;
  if (snapshot.root !== value) {
    const currentMarks = snapshot.owner ? state.field(snapshot.owner, key) : [];
    if (
      !isObject(snapshot.root) &&
      scalar(value) &&
      currentMarks.length &&
      snapshot.owner
    ) {
      state.putField(
        snapshot.owner,
        key,
        state.convert(
          currentMarks,
          value,
          'fastify.validation.coerce',
          location
        )
      );
      snapshot.sealed = true;
      return;
    }
    if (!isObject(snapshot.root) && scalar(value) && snapshot.owner)
      state.putField(snapshot.owner, key, []);
    state.gap(`fastify.${key}_validation_boundary`);
    snapshot.blocked = true;
    snapshot.sealed = true;
    return;
  }
  if (snapshot.missing) {
    snapshot.sealed = true;
    return;
  }
  for (const item of snapshot.objects) {
    for (const [field, previous] of item.fields) {
      const descriptor = Object.getOwnPropertyDescriptor(item.object, field);
      if (!descriptor || !('value' in descriptor)) {
        state.putField(item.object, field, []);
        continue;
      }
      if (Object.is(descriptor.value, previous.before)) continue;
      if (scalar(descriptor.value)) {
        // Instrumented user assignments clear field marks when they replace
        // input with a constant. Only an uninstrumented validation mutation
        // leaves current marks in place and may be carried through a scalar
        // coercion; the pre-validation snapshot is only the before image.
        const currentMarks = state.field(item.object, field);
        if (currentMarks?.length) {
          const marks = state.convert(
            currentMarks,
            descriptor.value,
            'fastify.validation.coerce',
            location
          );
          state.putField(item.object, field, marks);
        } else {
          state.putField(item.object, field, []);
        }
      } else {
        state.putField(item.object, field, []);
        state.gap(`fastify.${key}_validation_boundary`);
      }
    }
  }
  snapshot.sealed = true;
}

const validationCarriers = new WeakMap();

function releaseValidationCarriers(state) {
  const carriers = validationCarriers.get(state);
  if (!carriers) return;
  for (const snapshot of carriers.values()) {
    // Keep only the sealed/blocked decision for later sourceAccessor calls;
    // request containers must not remain reachable through validation state.
    snapshot.sealed = true;
    snapshot.root = undefined;
    snapshot.marks = [];
    snapshot.owner = undefined;
    snapshot.objects.length = 0;
  }
}

function fastifyState(request) {
  return request?.[FASTIFY_STATE] || request?.raw?.[FASTIFY_STATE];
}

function setFastifyState(request, state) {
  if (!request || !state) return;
  try {
    Object.defineProperty(request, FASTIFY_STATE, {
      value: state,
      configurable: true,
    });
  } catch {
    request[FASTIFY_STATE] = state;
  }
  try {
    if (request.raw)
      Object.defineProperty(request.raw, FASTIFY_STATE, {
        value: state,
        configurable: true,
      });
  } catch {
    try {
      if (request.raw) request.raw[FASTIFY_STATE] = state;
    } catch {
      state.gap('fastify_state_association_failed');
    }
  }
}

function installFastifyAccessors(request, state) {
  if (!request || !state || !state.collection_enabled) return;
  registerAccessor(
    state,
    request,
    'headers',
    'http.request.header',
    'header',
    'fastify.request.headers',
    undefined,
    true
  );
  registerAccessor(
    state,
    request,
    'query',
    'http.request.parameter',
    'query',
    'fastify.request.query',
    'query',
    true
  );
  registerAccessor(
    state,
    request,
    'params',
    'http.request.path',
    'path',
    'fastify.request.params',
    'params',
    true
  );
  registerAccessor(
    state,
    request,
    'body',
    'http.request.body',
    'body',
    'fastify.request.body',
    'body',
    true
  );
  try {
    captureAccessorValue(
      state,
      request.raw?.headers || request.headers,
      'headers',
      'http.request.header',
      'header',
      'fastify.request.headers',
      undefined,
      true
    );
  } catch {
    state.gap('fastify_headers_capture_failed');
  }
  try {
    rememberCarrier(
      state,
      'query',
      request.query,
      'http.request.parameter',
      'query',
      'fastify.request.query',
      request
    );
  } catch {
    state.gap('fastify_query_capture_failed');
  }
  try {
    rememberCarrier(
      state,
      'params',
      request.params,
      'http.request.path',
      'path',
      'fastify.request.params',
      request
    );
  } catch {
    state.gap('fastify_params_capture_failed');
  }
}

function releaseOnResponse(response, state) {
  if (!response || typeof response.once !== 'function') return;
  const release = () => releaseValidationCarriers(state);
  try {
    response.once('finish', release);
    response.once('close', release);
    response.once('error', release);
  } catch {
    state.gap('fastify_validation_cleanup_registration_failed');
  }
}

function bindHook(request, callback, done) {
  const state = fastifyState(request);
  let doneCalled = false;
  const finish = () => {
    if (doneCalled || typeof done !== 'function') return;
    doneCalled = true;
    done();
  };
  const run = () => {
    try {
      callback(state);
    } catch {
      state?.gap('fastify_hook_failed');
    }
    finish();
  };
  return state ? bind(state, run) : run();
}

function installFastifyHooks(app) {
  if (!app || typeof app.addHook !== 'function') return false;
  if (app[PATCHED]) return true;
  try {
    app.addHook('onRequest', function onRequest(request, reply, done) {
      const state = safeBegin(request?.raw, reply?.raw, metadata(request?.raw));
      if (state) {
        setFastifyState(request, state);
        installFastifyAccessors(request, state);
        releaseOnResponse(reply?.raw, state);
      }
      return bindHook(request, () => {}, done);
    });
    app.addHook('preValidation', function preValidation(request, _reply, done) {
      return bindHook(
        request,
        state => {
          if (!state || !state.collection_enabled) return;
          try {
            // Query and route params were captured at onRequest. Refresh only
            // their pre-validation snapshots here so instrumented user writes
            // remain clean; body capture starts at this boundary.
            rememberCarrier(
              state,
              'query',
              request.query,
              'http.request.parameter',
              'query',
              'fastify.request.query',
              request,
              false
            );
            rememberCarrier(
              state,
              'params',
              request.params,
              'http.request.path',
              'path',
              'fastify.request.params',
              request,
              false
            );
            const body = request.body;
            rememberCarrier(
              state,
              'body',
              body,
              'http.request.body',
              'body',
              'fastify.request.body',
              request
            );
          } catch {
            state.gap('fastify_body_capture_failed');
          }
        },
        done
      );
    });
    app.addHook('preHandler', function preHandler(request, _reply, done) {
      return bindHook(
        request,
        state => {
          if (!state) return;
          try {
            const route = request?.routeOptions?.url || request?.routerPath;
            if (typeof route === 'string') {
              state.request.route = route;
              state.request.route_status = 'observed';
            }
            reconcileCarrier(
              state,
              'query',
              request.query,
              'fastify.validation.query'
            );
            reconcileCarrier(
              state,
              'params',
              request.params,
              'fastify.validation.params'
            );
            reconcileCarrier(
              state,
              'body',
              request.body,
              'fastify.validation.body'
            );
          } finally {
            releaseValidationCarriers(state);
          }
        },
        done
      );
    });
    app.addHook('onResponse', function onResponse(request, _reply, done) {
      return bindHook(
        request,
        state => {
          const route = request?.routeOptions?.url || request?.routerPath;
          if (state && typeof route === 'string') {
            state.request.route = route;
            state.request.route_status = 'observed';
          }
        },
        done
      );
    });
    app.addHook('onError', function onError(request, _reply, error, done) {
      return bindHook(
        request,
        state => {
          if (!state) return;
          try {
            state.request.error_type = errorType(error);
          } finally {
            releaseValidationCarriers(state);
          }
        },
        done
      );
    });
    app.addHook('onRequestAbort', function onRequestAbort(request) {
      return bindHook(request, state => {
        if (!state) return;
        try {
          state.gap('request_aborted');
        } finally {
          releaseValidationCarriers(state);
        }
      });
    });
    Object.defineProperty(app, PATCHED, { value: true, configurable: true });
    return true;
  } catch {
    startupGap('fastify_hook_install_failed');
    return false;
  }
}

function copyFunctionSurface(wrapper, original) {
  for (const key of Reflect.ownKeys(original)) {
    if (
      key === 'length' ||
      key === 'name' ||
      key === 'prototype' ||
      key === 'caller' ||
      key === 'arguments'
    )
      continue;
    const descriptor = Object.getOwnPropertyDescriptor(original, key);
    if (!descriptor) continue;
    try {
      Object.defineProperty(wrapper, key, descriptor);
    } catch {
      /* static metadata is optional */
    }
  }
}

function repairFactoryAliases(wrapper, original) {
  for (const key of ['default', 'fastify']) {
    const descriptor = Object.getOwnPropertyDescriptor(wrapper, key);
    if (!descriptor || descriptor.value !== original) continue;
    try {
      Object.defineProperty(wrapper, key, { ...descriptor, value: wrapper });
    } catch {
      /* aliases are advisory */
    }
  }
}

function wrapFastifyFactory(original) {
  if (typeof original !== 'function' || original[WRAPPED]) return original;
  const wrapped = function fastifyFactory(...args) {
    const app = Reflect.apply(original, this, args);
    try {
      if (!installFastifyHooks(app))
        startupGap('fastify_instance_shape_unsupported');
    } catch {
      startupGap('fastify_factory_patch_failed');
    }
    return app;
  };
  copyFunctionSurface(wrapped, original);
  repairFactoryAliases(wrapped, original);
  markWrapped(wrapped, original, WRAPPED);
  return wrapped;
}

function replaceExport(exports, key, replacement) {
  if (!exports || typeof exports !== 'object') return exports;
  try {
    const descriptors = Object.getOwnPropertyDescriptors(exports);
    descriptors[key] = {
      value: replacement,
      enumerable: true,
      configurable: true,
      writable: true,
    };
    return Object.create(Object.getPrototypeOf(exports), descriptors);
  } catch {
    return exports;
  }
}

function factoryCandidate(value) {
  if (typeof value === 'function') return value;
  if (!value || typeof value !== 'object') return undefined;
  if (typeof value.default === 'function') return value.default;
  if (typeof value.fastify === 'function') return value.fastify;
  return undefined;
}

function importNamespace(value) {
  try {
    // import-in-the-middle exposes a mutable Module proxy whose setter updates
    // the generated wrapper's live binding. Returning an object clone here
    // would make that clone the default export, so identify it before using
    // the CJS object replacement path below.
    return (
      value?.[Symbol.toStringTag] === 'Module' && Object.isExtensible(value)
    );
  } catch {
    return false;
  }
}

function installFastify(exports) {
  if (typeof exports === 'function') return wrapFastifyFactory(exports);
  if (!exports || typeof exports !== 'object') {
    startupGap('fastify_export_shape_unsupported');
    return exports;
  }
  let patched = exports;
  const wrappers = new Map();
  const liveNamespace = importNamespace(exports);
  for (const key of ['default', 'fastify', 'module.exports']) {
    const original = factoryCandidate(exports[key]);
    if (!original) continue;
    let wrapped = wrappers.get(original);
    if (!wrapped) {
      wrapped = wrapFastifyFactory(original);
      wrappers.set(original, wrapped);
    }
    if (liveNamespace) {
      // import-in-the-middle's hook can update every live binding through the
      // proxy. Keep named `fastify` and synthetic `module.exports` aligned with
      // the default factory, while returning the function for callHookFn's
      // default assignment.
      try {
        exports[key] = wrapped;
      } catch {
        /* an unavailable alias is a gap below */
      }
    } else {
      patched = replaceExport(patched, key, wrapped);
    }
  }
  if (liveNamespace) {
    const wrapped = wrappers.values().next().value;
    if (wrapped) return wrapped;
  }
  if (patched !== exports) return patched;
  startupGap('fastify_export_shape_unsupported');
  return exports;
}

export function installFramework(name, exports, version = '') {
  const framework = normalizedName(name);
  const major = versionMajor(version);
  if (framework === 'express') {
    if (major && !expressVersions.has(major)) {
      startupGap(`unsupported_express_version:${text(version)}`);
      return exports;
    }
    return installExpress(exports);
  }
  if (framework === 'fastify') {
    if (major && !fastifyVersions.has(major)) {
      startupGap(`unsupported_fastify_version:${text(version)}`);
      return exports;
    }
    return installFastify(exports);
  }
  startupGap(`unsupported_framework:${text(name)}`);
  return exports;
}

export default installFramework;
