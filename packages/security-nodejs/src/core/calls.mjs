import { current } from './runtime.mjs';
import { p, isObject, binding } from './values.mjs';
import { types, promisify } from 'node:util';

const functions = new WeakMap(),
  models = new WeakMap(),
  promises = new WeakMap(),
  namespaces = new WeakMap(),
  boundFunctions = new WeakMap();
const frames = [];
const modules = new Map(),
  resolutions = new Map(),
  exportedFunctions = new Map(),
  exportStars = new Map();
const unwrap = fn => {
  for (let i = 0; typeof fn === 'function' && i < 8; i++) {
    if (functions.has(fn) || models.has(fn)) return fn;
    if (types.isProxy(fn)) return fn;
    const descriptor = Object.getOwnPropertyDescriptor(fn, '__original');
    if (!descriptor || typeof descriptor.value !== 'function') return fn;
    fn = descriptor.value;
  }
  return fn;
};
export function fn(value, id, name = '') {
  functions.set(value, id);
  if (!value.name && name)
    Object.defineProperty(value, 'name', { value: name, configurable: true });
  return value;
}
export function method(object, key, id, kind = 'value') {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (typeof descriptor?.[kind] === 'function')
    functions.set(descriptor[kind], id);
  return object;
}
export function model(fn, handlers) {
  if (typeof fn === 'function') models.set(fn, handlers);
}
export function enter(id, value) {
  const pending = frames.at(-1);
  return pending &&
    (pending.id === id || (value && pending.fn === value)) &&
    !pending.entered
    ? ((pending.entered = true), pending)
    : { args: [], result: { m: [] }, external: true };
}
export function param(
  frame,
  index,
  value,
  path = [],
  rest = false,
  excluded = []
) {
  if (rest === 'parameter') {
    const state = current();
    if (state)
      for (let i = index; i < frame.args.length; i++)
        state.putField(value, String(i - index), frame.args[i].m);
    return [];
  }
  return binding(frame.args[index] || p(value), path, value, rest, excluded);
}
export function defaultBoundary(frame, index, nested = false) {
  if (nested || frame.external || frame.args[index]?.v === undefined)
    current()?.gap('default_expression_propagation');
}
export function entered(frame, argumentObject, aliases = []) {
  const state = current();
  if (state && isObject(argumentObject)) {
    frame.args.forEach((pair, i) =>
      state.putField(argumentObject, String(i), pair.m)
    );
    if (aliases.length) {
      const entry = state.record(argumentObject, true);
      if (entry)
        entry.data = {
          kind: 'arguments',
          aliases: new Map(
            aliases.map(([index, get, set]) => [String(index), { get, set }])
          ),
        };
    }
  }
  frame.args = [];
}
export function property(receiver, key, operation, kind, location, arg) {
  let object = receiver.v,
    accessor;
  if (current() && isObject(object) && !types.isProxy(object)) {
    for (let depth = 0; object && depth < 16; depth++) {
      if (types.isProxy(object)) {
        current().gap('proxy_property_propagation');
        break;
      }
      const descriptor = Object.getOwnPropertyDescriptor(object, key.v);
      if (descriptor) {
        accessor = descriptor[kind];
        break;
      }
      object = Object.getPrototypeOf(object);
    }
  }
  const frame = {
    fn: accessor,
    id: functions.get(accessor),
    args: arg ? [arg] : [],
    result: { m: [] },
    location,
    entered: false,
  };
  let value;
  frames.push(frame);
  try {
    value = operation();
  } finally {
    frames.pop();
    frame.fn = undefined;
    frame.args = [];
  }
  if (frame.entered && types.isPromise(value) && !promises.has(value))
    promises.set(value, frame);
  return p(value, frame.entered ? returnedMarks(frame) : []);
}
export function namespace(pair, parent, specifier) {
  if (isObject(pair.v)) namespaces.set(pair.v, { parent, specifier });
  return pair;
}
export function namespaceMarks(object, key, value) {
  const ns = isObject(object) && namespaces.get(object);
  if (!ns) return [];
  importValue(value, ns.parent, ns.specifier, key);
  return importMarks(ns.parent, ns.specifier, key);
}
export function declareFunctionExport(url, name, id) {
  if (exportedFunctions.size < 10000)
    exportedFunctions.set(url + '\0' + name, id);
}
export function importValue(value, parent, specifier, name) {
  if (typeof value === 'function') {
    const id = exportedFunctions.get(
      resolutions.get(parent + '\0' + specifier) + '\0' + name
    );
    if (id) functions.set(value, id);
  }
  return value;
}
export function ret(frame, pair) {
  frame.result = {
    m: pair.m,
    record: isObject(pair.v) ? promises.get(pair.v) : undefined,
  };
  return pair.v;
}
const returnedMarks = (record, depth = 0) =>
  depth > 16
    ? []
    : record?.result?.record
      ? returnedMarks(record.result.record, depth + 1)
      : record?.result?.m || [];
export function awaited(pair, value) {
  const state = current();
  const record = isObject(pair.v) ? promises.get(pair.v) : undefined;
  materialize(record, value, state);
  return p(
    value,
    record
      ? state?.step(returnedMarks(record), 'await', '', {
          length: typeof value === 'string' ? value.length : undefined,
        })
      : pair.m
  );
}
function materialize(record, value, state) {
  if (!record || !state) return;
  // A Promise DAG can share results exponentially often. Metadata and result
  // identities both matter, and the visit set must stay local to this request.
  const visited = new Map();
  let remaining = 4096;
  const spend = () => {
    if (remaining-- > 0) return true;
    state.gap('promise_metadata_work_limit');
    return false;
  };
  function visit(record, value, depth) {
    if (!record) return true;
    if (!spend()) return false;
    if (visited.get(record)?.has(value)) return true;
    if (depth > 32) {
      state.gap('promise_metadata_depth');
      return true;
    }
    if (!visited.has(record)) visited.set(record, new Set());
    visited.get(record).add(value);
    if (record.result?.record)
      return visit(record.result.record, value, depth + 1);
    if (!record.items || !Array.isArray(value)) return true;
    if (types.isProxy(value)) {
      state.gap('promise_result_mutated');
      return true;
    }
    for (let i = 0; i < record.items.length; i++) {
      if (!spend()) return false;
      const item = record.items[i],
        descriptor = Object.getOwnPropertyDescriptor(value, String(i));
      if (!descriptor || !('value' in descriptor)) {
        state.gap('promise_result_mutated');
        continue;
      }
      let data = descriptor.value;
      const marks = item.record ? returnedMarks(item.record) : item.m;
      if (record.settled) {
        if (!isObject(data) || types.isProxy(data)) {
          state.gap('promise_result_mutated');
          continue;
        }
        const status = Object.getOwnPropertyDescriptor(data, 'status');
        if (!status || !('value' in status)) {
          state.gap('promise_result_mutated');
          continue;
        }
        if (status.value !== 'fulfilled') continue;
        const result = Object.getOwnPropertyDescriptor(data, 'value');
        if (!result || !('value' in result)) {
          state.gap('promise_result_mutated');
          continue;
        }
        state.putField(data, 'value', marks);
        data = result.value;
      } else state.putField(value, String(i), marks);
      if (!visit(item.record, data, depth + 1)) return false;
    }
    return true;
  }
  visit(record, value, 0);
}
function callback(original, argMarks, onResult) {
  if (typeof original !== 'function') return original;
  return function (...args) {
    const call = { v: original, m: [], receiver: p(this) };
    const result = invoke(
      call,
      args.map((v, i) => p(v, argMarks(i))),
      ''
    );
    onResult?.(result);
    return result.v;
  };
}
function resolutionModel(record, rejected = false) {
  // Resolver functions may be cached after settlement. This scope must not
  // capture the executor or the enclosing invocation's business arguments.
  return {
    before: values => {
      if (record.settled) return;
      if (!rejected)
        record.result = {
          m: values[0]?.m || [],
          record: isObject(values[0]?.v)
            ? promises.get(values[0].v)
            : undefined,
        };
      record.settled = true;
    },
  };
}
function derivedFunction(actual, args, receiver, value) {
  if (typeof value !== 'function') return;
  if (actual === Function.prototype.bind)
    boundFunctions.set(value, {
      fn: unwrap(receiver.v),
      receiver: args[0] || p(undefined),
      args: args.slice(1),
    });
  if (actual === promisify) {
    const original = unwrap(args[0]?.v),
      handler = models.get(original);
    // Custom promisifiers can change the argument contract. Adapters opt in
    // only when the returned function preserves the original sink arguments.
    if (handler?.promisify) model(value, { before: handler.before });
  }
}
export function invoke(callee, args, location = '', construct = false) {
  const target = callee.v,
    receiver = callee.receiver || p(undefined);
  const actual = unwrap(target),
    state = current();
  if (!state) {
    const value = construct
      ? Reflect.construct(
          target,
          args.map(a => a.v)
        )
      : Reflect.apply(
          target,
          receiver.v,
          args.map(a => a.v)
        );
    derivedFunction(actual, args, receiver, value);
    return p(value);
  }
  let targetForFrame = actual,
    frameArgs = args,
    modelReceiver = receiver;
  if (actual === Function.prototype.call && typeof receiver.v === 'function') {
    targetForFrame = unwrap(receiver.v);
    frameArgs = args.slice(1);
    modelReceiver = args[0] || p(undefined);
  }
  if (actual === Function.prototype.apply && typeof receiver.v === 'function') {
    targetForFrame = unwrap(receiver.v);
    const list = args[1]?.v;
    modelReceiver = args[0] || p(undefined);
    frameArgs =
      Array.isArray(list) && !types.isProxy(list)
        ? Array.from({ length: Math.min(list.length, 4096) }, (_, i) => ({
            v: Object.getOwnPropertyDescriptor(list, String(i))?.value,
            m: state.field(list, String(i)),
          }))
        : [];
    if (
      list != null &&
      (!Array.isArray(list) || types.isProxy(list) || list.length > 4096)
    )
      state.gap('apply_arguments_coverage');
  }
  const bound = boundFunctions.get(targetForFrame);
  if (bound) {
    targetForFrame = bound.fn;
    frameArgs = [...bound.args, ...frameArgs];
    modelReceiver = bound.receiver;
  }
  const frame = {
    fn: targetForFrame,
    id: functions.get(targetForFrame),
    args: frameArgs,
    result: { m: [] },
    location,
    entered: false,
  };
  const handler = models.get(targetForFrame);
  let actualArgs = args.map(a => a.v),
    promiseResult,
    callbackResult;
  if (construct && actual === Promise && typeof actualArgs[0] === 'function') {
    promiseResult = { result: { m: [] } };
    const executor = actualArgs[0];
    actualArgs[0] = function (resolve, reject) {
      model(resolve, resolutionModel(promiseResult));
      model(reject, resolutionModel(promiseResult, true));
      return invoke(p(executor), [p(resolve), p(reject)], location).v;
    };
  }
  if (
    !construct &&
    [
      Promise.prototype.then,
      Promise.prototype.catch,
      Promise.prototype.finally,
    ].includes(actual)
  ) {
    const parent = promises.get(receiver.v);
    promiseResult = { result: { m: [] } };
    if (actual === Promise.prototype.then) {
      const success = actualArgs[0];
      actualArgs = [
        typeof success === 'function'
          ? function (value) {
              materialize(parent, value, current());
              const result = invoke(
                p(success),
                [p(value, returnedMarks(parent))],
                location
              );
              promiseResult.result = {
                m: result.m,
                record: isObject(result.v) ? promises.get(result.v) : undefined,
              };
              return result.v;
            }
          : success,
        callback(
          actualArgs[1],
          () => [],
          result => {
            promiseResult.result = { m: result.m };
          }
        ),
      ];
      if (typeof args[0]?.v !== 'function')
        promiseResult = parent || promiseResult;
    } else if (actual === Promise.prototype.catch) {
      promiseResult.result.record = parent;
      actualArgs = [
        callback(
          actualArgs[0],
          () => [],
          result => {
            promiseResult.result = { m: result.m };
          }
        ),
      ];
    } else {
      promiseResult = parent || promiseResult;
      actualArgs = [callback(actualArgs[0], () => [], undefined)];
    }
  }
  if (!construct && actual === Promise.resolve) {
    promiseResult = (isObject(args[0]?.v) && promises.get(args[0].v)) || {
      result: { m: args[0]?.m || [] },
    };
  }
  if (
    !construct &&
    [Promise.all, Promise.allSettled].includes(actual) &&
    actualArgs[0] != null
  ) {
    const input = args[0];
    promiseResult = {
      result: { m: [] },
      items: [],
      settled: actual === Promise.allSettled,
    };
    actualArgs[0] = {
      *[Symbol.iterator]() {
        let index = 0;
        for (const value of input.v) {
          if (index < 4096)
            promiseResult.items.push({
              m: Array.isArray(input.v)
                ? state.field(input.v, String(index))
                : [],
              record: isObject(value) ? promises.get(value) : undefined,
            });
          else state.gap('promise_aggregation_limit');
          index++;
          yield value;
        }
      },
    };
  }
  const arrayMethods = [
    'map',
    'forEach',
    'filter',
    'find',
    'findIndex',
    'some',
    'every',
    'reduce',
    'reduceRight',
  ];
  const arrayMethod =
    !construct && arrayMethods.find(name => actual === Array.prototype[name]);
  if (arrayMethod && typeof actualArgs[0] === 'function') {
    const callbackFn = actualArgs[0],
      resultMarks = [],
      reduce = arrayMethod.startsWith('reduce');
    let accumulator = args[1]?.m || [],
      seen = false;
    actualArgs[0] = function (...values) {
      const index = values[reduce ? 2 : 1];
      const elementMarks = state.field(receiver.v, String(index));
      if (reduce && !seen && args.length < 2)
        accumulator = state.field(
          receiver.v,
          String(index + (arrayMethod === 'reduceRight' ? 1 : -1))
        );
      seen = true;
      const pairs = values.map((v, i) =>
        p(
          v,
          reduce
            ? i === 0
              ? accumulator
              : i === 1
                ? elementMarks
                : []
            : i === 0
              ? elementMarks
              : []
        )
      );
      const result = invoke(
        { v: callbackFn, m: [], receiver: p(this) },
        pairs,
        location
      );
      if (reduce) accumulator = result.m;
      if (arrayMethod === 'map' && resultMarks.length < 4096)
        resultMarks.push([String(index), result.m]);
      if (arrayMethod === 'filter' && result.v && resultMarks.length < 4096)
        resultMarks.push([String(resultMarks.length), elementMarks]);
      if (arrayMethod === 'find' && result.v) accumulator = elementMarks;
      return result.v;
    };
    callbackResult = value => {
      if (Array.isArray(value))
        for (const [key, marks] of resultMarks)
          state.putField(value, key, marks);
      return reduce || arrayMethod === 'find' ? accumulator : [];
    };
  }
  const timerOffset =
    actual === globalThis.setTimeout || actual === globalThis.setInterval
      ? 2
      : actual === globalThis.setImmediate || actual === process.nextTick
        ? 1
        : 0;
  if (timerOffset && typeof actualArgs[0] === 'function')
    actualArgs[0] = callback(
      actualArgs[0],
      i => args[i + timerOffset]?.m || []
    );
  if (state && handler?.before) {
    try {
      handler.before(frameArgs, modelReceiver, location, state);
    } catch {
      state.gap('sink_model_failed');
    }
  }
  let value;
  frames.push(frame);
  try {
    value = construct
      ? Reflect.construct(target, actualArgs)
      : Reflect.apply(target, receiver.v, actualArgs);
  } finally {
    // A cached settled Promise may outlive the request; its metadata must not
    // retain the invoked function's closure or the original business arguments.
    frames.pop();
    frame.fn = undefined;
    frame.args = [];
  }
  let marks = frame.entered ? returnedMarks(frame) : [];
  if (callbackResult) marks = callbackResult(value);
  if (handler?.after && state) {
    try {
      marks =
        handler.after(value, frameArgs, modelReceiver, location, state) ||
        marks;
    } catch {
      state.gap('propagation_model_failed');
    }
  }
  derivedFunction(actual, args, receiver, value);
  if (promiseResult && isObject(value)) promises.set(value, promiseResult);
  else if (frame.entered && types.isPromise(value) && !promises.has(value))
    promises.set(value, frame);
  if (
    !handler &&
    !frame.entered &&
    !promiseResult &&
    !callbackResult &&
    value != null
  ) {
    const carriesMarks = pair =>
      pair.m.length || state.record(pair.v)?.fields.size;
    if (carriesMarks(receiver) || args.some(carriesMarks))
      state.gap('unmodeled_call_result');
  }
  return p(value, marks);
}
export function resolveModule(parent, specifier, url) {
  if (resolutions.size < 20000) resolutions.set(parent + '\0' + specifier, url);
}
export function exportMarks(url, name, getter) {
  if (!modules.has(url) && modules.size < 10000) modules.set(url, new Map());
  modules.get(url)?.set(name, getter);
}
export function exportAll(url, specifier) {
  if (!exportStars.has(url) && exportStars.size < 10000)
    exportStars.set(url, new Set());
  exportStars.get(url)?.add(specifier);
}
let importQuery;
export function importMarks(parent, specifier, name) {
  const state = current();
  if (!state) return [];
  const root = !importQuery;
  if (root) importQuery = { state, seen: new Set(), remaining: 256, depth: 0 };
  try {
    return resolveImportMarks(parent, specifier, name, importQuery) || [];
  } catch {
    state.gap('export_metadata_failed');
    return [];
  } finally {
    if (root) importQuery = undefined;
  }
}
function resolveImportMarks(parent, specifier, name, query) {
  if (query.remaining-- <= 0) {
    query.state.gap('export_metadata_limit');
    return;
  }
  if (query.depth >= 32) {
    query.state.gap('export_metadata_depth');
    return;
  }
  const url = resolutions.get(parent + '\0' + specifier);
  if (!url) return;
  const key = url + '\0' + name;
  if (query.seen.has(key)) return;
  query.seen.add(key);
  query.depth++;
  try {
    const table = modules.get(url);
    if (table?.has(name)) return table.get(name)() || [];
    if (name === 'default') return;
    for (const star of exportStars.get(url) || []) {
      if (query.remaining <= 0) {
        query.state.gap('export_metadata_limit');
        return;
      }
      const marks = resolveImportMarks(url, star, name, query);
      // An empty array is a resolved, clean binding. Only a missing binding
      // should continue through other stars; named re-exports share this query.
      if (marks !== undefined) return marks;
    }
  } finally {
    query.depth--;
  }
}
export function defaultExport(url, pair) {
  const marks = pair.m;
  exportMarks(url, 'default', () => marks);
  return pair.v;
}
