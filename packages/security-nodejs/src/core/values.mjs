import { current } from './runtime.mjs';
import { property, namespaceMarks } from './calls.mjs';
import rawProperty from './property.cjs';
import { types } from 'node:util';

export const isObject = v =>
  v !== null && (typeof v === 'object' || typeof v === 'function');
export const propertyKey = key =>
  typeof key === 'symbol'
    ? key
    : ['string', 'number', 'bigint', 'boolean', 'undefined'].includes(
          typeof key
        ) || key === null
      ? String(key)
      : undefined;
export function p(v, m = []) {
  const state = current();
  return { v, m: state ? state.valid(m?.length ? m : state.marks(v)) : [] };
}
export const val = value => value.v;
export const unref = ({ v, m, skip }) => ({ v, m, skip });
export const skipped = () => ({ v: undefined, m: [], skip: true });
export function gap(reason) {
  current()?.gap(reason);
}
const accessors = new WeakMap();
export function sourceAccessor(object, key, capture) {
  let fields = accessors.get(object);
  if (!fields) {
    fields = new Map();
    accessors.set(object, fields);
  }
  fields.set(key, capture);
}
export function key(receiver, key) {
  if (receiver.v == null) receiver.v[key.v];
  return p(
    typeof key.v === 'symbol' || typeof key.v === 'string'
      ? key.v
      : Reflect.ownKeys({ [key.v]: null })[0]
  );
}
export function get(receiver, key, location = '') {
  if (receiver.v == null) receiver.v[key.v];
  const converted =
    key.v === null || !isObject(key.v)
      ? key
      : { v: Reflect.ownKeys({ [key.v]: null })[0], m: [] };
  const read = property(
    receiver,
    converted,
    () => receiver.v[converted.v],
    'get',
    location
  );
  const v = read.v;
  const state = current(),
    k = propertyKey(converted.v);
  let m = state && k !== undefined ? state.field(receiver.v, k) : [];
  if (!m.length) m = read.m.length ? read.m : namespaceMarks(receiver.v, k, v);
  if (state && k !== undefined && isObject(receiver.v)) {
    try {
      const capture = accessors.get(receiver.v)?.get(k);
      if (capture) m = capture(state, v, location) || m;
      if (typeof receiver.v === 'string' && /^\d+$/.test(k))
        m = state.step(receiver.m, 'string.index', location, {
          from: +k,
          to: +k + 1,
          offset: -Number(k),
        });
      const entry = state.record(receiver.v);
      if (entry?.data?.kind === 'arguments') {
        const descriptor = Object.getOwnPropertyDescriptor(receiver.v, k);
        if (!descriptor?.writable) entry.data.aliases.delete(k);
        m = entry.data.aliases.get(k)?.get() || m;
      }
      if (entry?.data?.kind === 'url' && typeof v === 'string') {
        const bounds = entry.data.parts[k];
        if (bounds)
          m = state.step(entry.marks, 'url.' + k, location, {
            from: bounds[0],
            to: bounds[1],
            offset: -bounds[0],
            length: v.length,
          });
      }
    } catch {
      state.gap('property_model_failed');
    }
  }
  if (
    state &&
    typeof receiver.v === 'string' &&
    k !== undefined &&
    /^\d+$/.test(k)
  )
    m = state.step(receiver.m, 'string.index', location, {
      from: +k,
      to: +k + 1,
      offset: -Number(k),
    });
  if (state && k === undefined) state.gap('computed_object_key');
  return {
    v,
    m: state ? state.valid(m?.length ? m : state.marks(v)) : [],
    receiver,
  };
}
export function set(receiver, key, value, strict = true) {
  // Ordinary assignment evaluates its RHS before PutValue converts the key.
  if (receiver.v == null)
    (strict ? rawProperty.setStrict : rawProperty.setLoose)(
      receiver.v,
      key.v,
      value.v
    );
  if (isObject(key.v))
    key = { v: Reflect.ownKeys({ [key.v]: null })[0], m: [] };
  property(
    receiver,
    key,
    () =>
      (strict ? rawProperty.setStrict : rawProperty.setLoose)(
        receiver.v,
        key.v,
        value.v
      ),
    'set',
    '',
    value
  );
  const k = propertyKey(key.v),
    state = current();
  if (state && k !== undefined) {
    if (isObject(receiver.v) && !types.isProxy(receiver.v)) {
      const descriptor = Object.getOwnPropertyDescriptor(receiver.v, k);
      if (descriptor && 'value' in descriptor && descriptor.writable) {
        state.putField(receiver.v, k, value.m);
        const entry = state.record(receiver.v);
        if (entry?.data?.kind === 'arguments')
          entry.data.aliases.get(k)?.set(value.m);
      } else state.putField(receiver.v, k, []);
    } else if (isObject(receiver.v)) state.gap('proxy_property_propagation');
    accessors.get(receiver.v)?.delete(k);
  } else if (state) state.gap('computed_object_key');
  return p(value.v, value.m);
}
export function del(receiver, key, strict = true) {
  const result = (strict ? rawProperty.deleteStrict : rawProperty.deleteLoose)(
    receiver.v,
    key.v
  );
  if (result) {
    const k = propertyKey(key.v);
    if (k !== undefined) {
      current()?.putField(receiver.v, k, []);
      current()?.record(receiver.v)?.data?.aliases?.delete(k);
      accessors.get(receiver.v)?.delete(k);
    }
  }
  return p(result);
}
export function pathMarks(value, path) {
  const state = current();
  if (!state) return [];
  let v = value.v,
    m = value.m;
  for (let i = 0; i < path.length; i++) {
    if (isObject(v) && types.isProxy(v)) {
      state.gap('destructuring_proxy_boundary');
      return [];
    }
    const key = String(path[i]);
    m = state.field(v, key);
    if (i < path.length - 1) {
      const descriptor = isObject(v)
        ? Object.getOwnPropertyDescriptor(v, key)
        : undefined;
      if (
        !descriptor ||
        (descriptor.value === undefined && 'value' in descriptor)
      )
        return [];
      if (!('value' in descriptor)) {
        state.gap('destructuring_accessor_boundary');
        return [];
      }
      v = descriptor.value;
    }
  }
  return state.valid(m);
}
export function binding(value, path, target, rest = false, excluded = []) {
  const state = current();
  if (!state) return [];
  if (rest && isObject(target)) {
    let origin = value.v;
    const parent = path.slice(0, -1);
    for (const key of parent) {
      if (isObject(origin) && types.isProxy(origin)) {
        state.gap('destructuring_proxy_boundary');
        return [];
      }
      const desc = isObject(origin)
        ? Object.getOwnPropertyDescriptor(origin, key)
        : undefined;
      if (!desc || !('value' in desc)) {
        state.gap('destructuring_accessor_boundary');
        return [];
      }
      origin = desc.value;
    }
    const fields = state.record(origin)?.fields;
    if (fields)
      for (const [key, marks] of fields) {
        if (rest === 'array') {
          const start = Number(path.at(-1));
          if (/^\d+$/.test(String(key)) && Number(key) >= start)
            state.putField(target, String(Number(key) - start), marks);
        } else if (!excluded.includes(key)) state.putField(target, key, marks);
      }
    return [];
  }
  return path.length ? pathMarks(value, path) : p(target, value.m).m;
}
export function object(value, entries) {
  const state = current();
  let remaining = 512;
  if (state)
    for (const [key, field, spread] of entries) {
      if (spread) {
        if (!isObject(field.v) && typeof field.v !== 'string') continue;
        const targetFields = state.record(value)?.fields;
        if (types.isProxy(field.v)) {
          state.gap('proxy_spread_propagation');
          targetFields?.clear();
          continue;
        }
        // Unmarked properties matter only when they overwrite an earlier mark.
        // Enumerating the input would allocate in proportion to business data.
        for (const k of targetFields?.keys() || []) {
          if (--remaining < 0) {
            state.gap('object_spread_field_limit');
            targetFields.clear();
            return p(value);
          }
          const descriptor = Object.getOwnPropertyDescriptor(field.v, k);
          if (descriptor?.enumerable) targetFields.delete(k);
        }
        for (const [k, marks] of state.record(field.v)?.fields || []) {
          if ((remaining -= 2) < 0) {
            state.gap('object_spread_field_limit');
            state.record(value)?.fields.clear();
            return p(value);
          }
          const descriptor = Object.getOwnPropertyDescriptor(field.v, k);
          if (!descriptor?.enumerable) continue;
          if (!('value' in descriptor)) {
            state.gap('spread_accessor_propagation');
            continue;
          }
          const result = Object.getOwnPropertyDescriptor(value, k);
          if (
            result &&
            'value' in result &&
            Object.is(result.value, descriptor.value)
          )
            state.putField(value, k, marks);
        }
      } else {
        const k = propertyKey(key);
        if (k !== undefined) {
          const descriptor = Object.getOwnPropertyDescriptor(value, k);
          if (
            descriptor &&
            'value' in descriptor &&
            Object.is(descriptor.value, field.v)
          )
            state.putField(value, k, field.m);
          else state.putField(value, k, []);
        } else state.gap('computed_object_key');
      }
    }
  return p(value);
}
export function array(pairs) {
  const result = pairs.map(pair => pair.v),
    state = current();
  if (state)
    pairs.forEach((pair, i) => state.putField(result, String(i), pair.m));
  return p(result);
}
export function* spread(pair) {
  const state = current();
  let index = 0;
  const nativeArray =
    Array.isArray(pair.v) &&
    !types.isProxy(pair.v) &&
    !Object.hasOwn(pair.v, Symbol.iterator);
  if (state && !nativeArray && (pair.m.length || isObject(pair.v)))
    state.gap('custom_iterator_propagation');
  for (const value of pair.v)
    yield p(value, nativeArray ? state?.field(pair.v, String(index++)) : []);
}
export function iterator(pair) {
  const it = { marks: [], value: undefined, iterable: null };
  it.iterable = (function* () {
    for (const item of spread(pair)) {
      it.marks = item.m;
      it.value = item.v;
      yield item.v;
    }
  })();
  return it;
}
export function thrown(pair) {
  if (pair.m.length) gap('exception_value_propagation');
  return pair.v;
}
