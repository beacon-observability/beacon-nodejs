import { model } from '../core/calls.mjs';
import path from 'node:path';
import { URL as NativeURL } from 'node:url';
import { types } from 'node:util';

const installed = new WeakSet();
let builtinsInstalled = false;
const urlGetters = new Map(
  [
    'href',
    'origin',
    'protocol',
    'username',
    'password',
    'host',
    'hostname',
    'port',
    'pathname',
    'search',
    'hash',
  ].map(key => [
    key,
    Object.getOwnPropertyDescriptor(NativeURL.prototype, key).get,
  ])
);

function isUrl(value) {
  if (!value || typeof value !== 'object') return false;
  let object = value;
  for (let depth = 0; object && depth < 16; depth++) {
    if (types.isProxy(object)) return false;
    object = Object.getPrototypeOf(object);
    if (object === NativeURL.prototype) return true;
  }
  return false;
}

function register(value, handlers) {
  if (typeof value !== 'function') return value;
  const chain = [];
  let current = value;
  for (let depth = 0; typeof current === 'function' && depth < 8; depth += 1) {
    if (!chain.includes(current)) chain.push(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, '__original');
    if (!descriptor || typeof descriptor.value !== 'function') break;
    current = descriptor.value;
  }
  for (const fn of chain) {
    if (!installed.has(fn)) installed.add(fn);
    model(fn, handlers);
  }
  return value;
}

function bounded(value, length = 1024) {
  if (value === undefined || value === null) return '';
  try {
    return String(value).slice(0, length);
  } catch {
    return '';
  }
}

function marks(pair) {
  return Array.isArray(pair?.m) ? pair.m : [];
}

function isString(value) {
  return typeof value === 'string';
}

function asString(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  try {
    return String(value);
  } catch {
    return '';
  }
}

function primitiveString(value) {
  if (value === null || value === undefined) return asString(value);
  const type = typeof value;
  return type === 'object' || type === 'function' ? null : asString(value);
}

function mergeMarks(state, values) {
  const result = [];
  for (const item of values) {
    for (const mark of state.valid(item || [])) {
      if (result.length >= state.maxMarks) break;
      result.push(mark);
    }
  }
  return result;
}

function converted(state, sourceMarks, value, operation, location) {
  const primitive = ['number', 'boolean', 'bigint'].includes(typeof value);
  if (
    !sourceMarks?.length ||
    !(
      isString(value) ||
      primitive ||
      (typeof Buffer !== 'undefined' && Buffer.isBuffer(value))
    )
  )
    return [];
  return state.convert(sourceMarks, value, operation, location);
}

function pairAndFieldMarks(pair, state) {
  if (!pair) return [];
  const result = [marks(pair)];
  const fields = state.record(pair.v)?.fields;
  if (fields) {
    let count = 0;
    for (const item of fields.values()) {
      if (++count > 4096) break;
      result.push(item);
    }
  }
  return mergeMarks(state, result);
}

function normalizeIndex(value, length, fallback) {
  if (
    value !== null &&
    (typeof value === 'object' ||
      typeof value === 'function' ||
      typeof value === 'symbol')
  )
    return null;
  const number = Number(value);
  if (Number.isNaN(number)) return fallback;
  if (number === -Infinity) return 0;
  if (number === Infinity) return length;
  const integer = number < 0 ? Math.ceil(number) : Math.floor(number);
  return Math.min(
    length,
    Math.max(0, integer < 0 ? length + integer : integer)
  );
}

function normalizeSubstringIndex(value, length, fallback) {
  if (
    value !== null &&
    (typeof value === 'object' ||
      typeof value === 'function' ||
      typeof value === 'symbol')
  )
    return null;
  const number = Number(value);
  if (Number.isNaN(number) || number <= 0) return 0;
  if (number === Infinity) return length;
  return Math.min(length, Math.floor(number));
}

function sliceBounds(value, startArg, endArg, mode) {
  const length = value.length;
  if (mode === 'substr') {
    if (
      startArg !== undefined &&
      (typeof startArg === 'object' ||
        typeof startArg === 'function' ||
        typeof startArg === 'symbol')
    )
      return null;
    let rawStart = startArg === undefined ? 0 : Number(startArg);
    if (Number.isNaN(rawStart)) rawStart = 0;
    if (rawStart === Infinity) rawStart = length;
    if (rawStart === -Infinity) rawStart = 0;
    // ToIntegerOrInfinity truncates toward zero: ceil for negatives, floor
    // for non-negative fractional offsets.
    const start =
      rawStart < 0
        ? Math.max(length + Math.ceil(rawStart), 0)
        : Math.min(Math.floor(rawStart), length);
    if (endArg === undefined) return [start, length];
    if (
      endArg !== null &&
      (typeof endArg === 'object' ||
        typeof endArg === 'function' ||
        typeof endArg === 'symbol')
    )
      return null;
    let amount = Number(endArg);
    if (Number.isNaN(amount) || amount <= 0) return [start, start];
    if (amount === Infinity) amount = length - start;
    return [start, Math.min(length, start + Math.floor(amount))];
  }
  const normalizer =
    mode === 'substring' ? normalizeSubstringIndex : normalizeIndex;
  let start = normalizer(startArg === undefined ? 0 : startArg, length, 0);
  let end = normalizer(endArg === undefined ? length : endArg, length, length);
  if (start === null || end === null) return null;
  if (mode === 'substring' && start > end) [start, end] = [end, start];
  return [start, end];
}

function stringSliceAfter(mode) {
  return (value, args, receiver, location, state) => {
    if (!isString(value) || !isString(receiver?.v) || !marks(receiver).length)
      return [];
    const bounds = sliceBounds(receiver.v, args[0]?.v, args[1]?.v, mode);
    if (!bounds) {
      state.gap(`string.${mode}_boundary_object`);
      return converted(
        state,
        marks(receiver),
        value,
        `string.${mode}`,
        location
      );
    }
    const [start, end] = bounds;
    return state.step(marks(receiver), `string.${mode}`, location, {
      from: start,
      to: end,
      offset: -start,
      length: value.length,
    });
  };
}

function stringConcatAfter(value, args, receiver, location, state) {
  if (!isString(value)) return [];
  const values = [receiver?.v, ...args.map(item => item?.v)];
  let offset = 0;
  const output = [];
  for (let index = 0; index < values.length; index += 1) {
    const item = values[index];
    const pair = index === 0 ? receiver : args[index - 1];
    const text = primitiveString(item);
    if (marks(pair).length && text === null) {
      // ToString on an application object may execute user code.  The native
      // call already did that conversion; avoid doing it a second time here
      // and retain conservative provenance for the resulting string.
      output.push(
        converted(state, marks(pair), value, 'string.concat', location)
      );
    } else if (marks(pair).length && text.length) {
      output.push(
        state.step(marks(pair), 'string.concat', location, {
          from: 0,
          to: text.length,
          offset: offset,
          length: value.length,
        })
      );
    }
    if (text !== null) offset += text.length;
  }
  return mergeMarks(state, output);
}

function arrayJoinAfter(value, args, receiver, location, state) {
  if (!isString(value) || !Array.isArray(receiver?.v)) return [];
  const output = [];
  const fields = state.record(receiver.v)?.fields;
  if (fields) {
    let count = 0;
    for (const [key, itemMarks] of fields) {
      if (++count > 4096) {
        state.gap('array.join_field_limit');
        break;
      }
      if (/^\d+$/.test(String(key)) && itemMarks?.length)
        output.push(converted(state, itemMarks, value, 'array.join', location));
    }
  }
  if (marks(receiver).length)
    output.push(
      converted(state, marks(receiver), value, 'array.join', location)
    );
  const separatorMarks = marks(args[0]);
  if (separatorMarks.length)
    output.push(
      converted(state, separatorMarks, value, 'array.join.separator', location)
    );
  return mergeMarks(state, output);
}

function urlCarrierStringMarks(
  value,
  carrier,
  fallback,
  location,
  state,
  operation
) {
  if (!isString(value) || !carrier || typeof carrier !== 'object') return [];
  const output = [];
  const componentTracked =
    state.record(carrier)?.data?.componentTracked === true;
  const fields = urlParts(carrier, state);
  for (const field of [
    'protocol',
    'username',
    'password',
    'hostname',
    'port',
    'pathname',
    'search',
    'hash',
  ]) {
    const fieldValue = fields[field];
    if (!isString(fieldValue)) continue;
    const fieldMarks = state.field(carrier, field);
    const range = urlFieldRange(value, field);
    if (fieldMarks.length && range)
      output.push(
        state.step(fieldMarks, operation, location, {
          from: 0,
          to: fieldValue.length,
          offset: range[0],
          length: value.length,
        })
      );
  }
  if (!output.length) {
    const hrefMarks = state.field(carrier, 'href');
    if (!componentTracked && hrefMarks.length)
      output.push(
        state.step(hrefMarks, operation, location, {
          from: 0,
          to: value.length,
          length: value.length,
        })
      );
    else if (!componentTracked)
      output.push(converted(state, fallback, value, operation, location));
  }
  return mergeMarks(state, output);
}

function primitiveConversionAfter(operation) {
  return (value, args, _receiver, location, state) => {
    if (
      value !== null &&
      !['string', 'number', 'boolean', 'bigint'].includes(typeof value)
    )
      return [];
    if (
      operation === 'string.convert' &&
      isString(value) &&
      isUrl(args[0]?.v)
    ) {
      return urlCarrierStringMarks(
        value,
        args[0].v,
        marks(args[0]),
        location,
        state,
        operation
      );
    }
    return converted(
      state,
      pairAndFieldMarks(args[0], state),
      value,
      operation,
      location
    );
  };
}

function bufferFromAfter(value, args, _receiver, location, state) {
  if (typeof Buffer === 'undefined' || !Buffer.isBuffer(value)) return [];
  const inputMarks = pairAndFieldMarks(args[0], state);
  const result = converted(state, inputMarks, value, 'buffer.from', location);
  if (result.length) state.put(value, result);
  return result;
}

function bufferToStringAfter(value, _args, receiver, location, state) {
  return isString(value)
    ? converted(state, marks(receiver), value, 'buffer.toString', location)
    : [];
}

function pathAfter(operation) {
  return (value, args, _receiver, location, state) => {
    if (!isString(value)) return [];
    return converted(
      state,
      mergeMarks(
        state,
        args.map(pair => pairAndFieldMarks(pair, state))
      ),
      value,
      operation,
      location
    );
  };
}

function sourceSegment(
  pair,
  sourceText,
  start,
  end,
  operation,
  location,
  state,
  outputLength
) {
  if (!marks(pair).length || start < 0 || end <= start) return [];
  return state.step(marks(pair), operation, location, {
    from: start,
    to: end,
    offset: -start,
    length: outputLength,
  });
}

function urlFieldRange(sourceText, field) {
  if (typeof sourceText !== 'string' || !sourceText) return undefined;
  const scheme = /^[A-Za-z][A-Za-z0-9+.-]*:/.exec(sourceText)?.[0] || '';
  let authorityStart = -1;
  if (sourceText.startsWith('//')) authorityStart = 2;
  else if (scheme && sourceText.startsWith('//', scheme.length))
    authorityStart = scheme.length + 2;
  let authorityEnd = authorityStart >= 0 ? sourceText.length : -1;
  if (authorityStart >= 0) {
    for (const delimiter of ['/', '?', '#']) {
      const index = sourceText.indexOf(delimiter, authorityStart);
      if (index >= 0) authorityEnd = Math.min(authorityEnd, index);
    }
  }
  const pathStart =
    authorityStart >= 0 ? authorityEnd : scheme ? scheme.length : 0;
  const hashStart = sourceText.indexOf('#', pathStart);
  const queryStart = sourceText.indexOf('?', pathStart);
  const pathEnd = Math.min(
    ...[sourceText.length, hashStart, queryStart].filter(index => index >= 0)
  );
  const queryEnd = hashStart >= 0 ? hashStart : sourceText.length;
  if (field === 'href') return [0, sourceText.length];
  if (field === 'protocol') return scheme ? [0, scheme.length] : undefined;
  if (field === 'pathname')
    return pathEnd > pathStart ? [pathStart, pathEnd] : undefined;
  if (field === 'search')
    return queryStart >= 0 && queryStart < queryEnd
      ? [queryStart, queryEnd]
      : undefined;
  if (field === 'hash')
    return hashStart >= 0 ? [hashStart, sourceText.length] : undefined;
  if (authorityStart < 0) return undefined;
  const authority = sourceText.slice(authorityStart, authorityEnd);
  const at = authority.lastIndexOf('@');
  const userInfoEnd = at >= 0 ? authorityStart + at : authorityStart;
  const hostStart = at >= 0 ? userInfoEnd + 1 : authorityStart;
  const userInfo = at >= 0 ? sourceText.slice(authorityStart, userInfoEnd) : '';
  if (field === 'username' && at >= 0) {
    const colon = userInfo.indexOf(':');
    return [authorityStart, colon >= 0 ? authorityStart + colon : userInfoEnd];
  }
  if (field === 'password' && at >= 0) {
    const colon = userInfo.indexOf(':');
    return colon >= 0 ? [authorityStart + colon + 1, userInfoEnd] : undefined;
  }
  let hostnameEnd = authorityEnd;
  let portStart = -1;
  if (sourceText[hostStart] === '[') {
    const closing = sourceText.indexOf(']', hostStart + 1);
    if (closing >= 0) {
      hostnameEnd = closing + 1;
      if (sourceText[hostnameEnd] === ':') portStart = hostnameEnd;
    }
  } else {
    const colon = sourceText.lastIndexOf(':', authorityEnd - 1);
    if (colon >= hostStart && sourceText.indexOf(':', hostStart) === colon) {
      hostnameEnd = colon;
      portStart = colon;
    }
  }
  if (field === 'host') return [hostStart, authorityEnd];
  if (field === 'hostname') return [hostStart, hostnameEnd];
  if (field === 'port')
    return portStart >= 0 ? [portStart + 1, authorityEnd] : undefined;
  if (field === 'origin') return [0, authorityEnd];
  return undefined;
}

function urlParts(value, state, keys = urlGetters.keys()) {
  const result = {};
  if (!value || typeof value !== 'object') return result;
  if (
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== NativeURL.prototype
  ) {
    state?.gap('unmodeled_url_carrier');
    return result;
  }
  for (const key of keys) {
    try {
      // Own overrides are business behavior, not a safe observation surface.
      if (Object.getOwnPropertyDescriptor(value, key)) {
        state?.gap('unmodeled_url_property');
        continue;
      }
      const item = Reflect.apply(urlGetters.get(key), value, []);
      if (typeof item === 'string') result[key] = item;
    } catch {
      state?.gap('unmodeled_url_carrier');
    }
  }
  return result;
}

function urlFieldMarks(pair, field, resultValue, result, location, state) {
  const fieldValue = result[field];
  if (!isString(fieldValue)) return [];
  // URL objects already carry component marks.  Reusing the object's whole
  // carrier mark here would turn a tainted query into a tainted host when a
  // URL is cloned or used as a constructor argument.
  if (isUrl(pair?.v)) {
    const fieldMarks = state.field(pair.v, field);
    if (fieldMarks.length) {
      return state.step(fieldMarks, `url.${field}`, location, {
        from: 0,
        to: fieldValue.length,
        offset: 0,
        length: fieldValue.length,
      });
    }
  }
  if (!marks(pair).length) return [];
  const sourceText = isUrl(pair?.v)
    ? urlParts(pair.v, state, ['href']).href || ''
    : isString(pair?.v)
      ? pair.v
      : '';
  const range = urlFieldRange(sourceText, field);
  return range
    ? sourceSegment(
        pair,
        sourceText,
        range[0],
        range[1],
        `url.${field}`,
        location,
        state,
        fieldValue.length
      )
    : [];
}

function putUrlCarrier(result, sourcePairs, location, state) {
  if (!result || typeof result !== 'object') return [];
  const pairs = sourcePairs.filter(Boolean);
  const fields = urlParts(result, state);
  const full = mergeMarks(
    state,
    pairs.map(pair =>
      converted(
        state,
        marks(pair),
        fields.href || '',
        'url.construct',
        location
      )
    )
  );
  state.put(result, full);
  const entry = state.record(result, true);
  if (entry) entry.data = { kind: 'url', parts: {}, componentTracked: true };
  for (const key of Object.keys(fields)) {
    const fieldMarks = mergeMarks(
      state,
      pairs.map(pair =>
        urlFieldMarks(pair, key, fields[key], fields, location, state)
      )
    );
    if (fieldMarks.length) state.putField(result, key, fieldMarks);
  }
  return full;
}

function urlConstructorAfter(value, args, _receiver, location, state) {
  if (!isUrl(value)) return [];
  return putUrlCarrier(value, [args[0], args[1]], location, state);
}

function urlToStringAfter(value, _args, receiver, location, state) {
  return urlCarrierStringMarks(
    value,
    receiver?.v,
    marks(receiver),
    location,
    state,
    'url.toString'
  );
}

function urlSearchParamsAfter(value, args, _receiver, location, state) {
  if (!value || typeof value !== 'object') return [];
  const input = args[0];
  const sourceText = primitiveString(input?.v);
  const outputText =
    sourceText === null ? bounded(value.toString?.(), 4096) : sourceText;
  const full = converted(
    state,
    marks(input),
    outputText,
    'url.search_params',
    location
  );
  state.put(value, full);
  if (full.length) state.putField(value, 'query', full);
  return full;
}

function urlSearchParamsMethodAfter(value, _args, receiver, location, state) {
  return isString(value)
    ? converted(state, marks(receiver), value, 'url.search_params', location)
    : [];
}

function requestAfter(value, args, _receiver, location, state) {
  if (!value || typeof value !== 'object' || typeof value.url !== 'string')
    return [];
  const source = args[0];
  const full = mergeMarks(
    state,
    [
      marks(source),
      state.field(source?.v, 'href'),
      state.field(source?.v, 'url'),
    ]
      .filter(Boolean)
      .map(item =>
        converted(state, item, value.url, 'request.construct', location)
      )
  );
  state.put(value, full);
  const entry = state.record(value, true);
  if (entry) entry.data = { kind: 'request', componentTracked: true };
  if (full.length) state.putField(value, 'url', full);
  const input = isUrl(source?.v)
    ? urlParts(source.v, state, ['href']).href || ''
    : primitiveString(source?.v);
  if (input !== null && input) {
    let fields;
    try {
      fields = urlParts(new NativeURL(value.url), state);
    } catch {
      fields = {};
    }
    for (const [field, valueForField] of Object.entries(fields)) {
      const direct =
        source?.v && typeof source.v === 'object'
          ? state.field(source.v, field)
          : [];
      const range = urlFieldRange(input, field);
      const fieldMarks = direct.length
        ? state.step(direct, `request.${field}`, location, {
            from: 0,
            to: valueForField.length,
            offset: 0,
            length: valueForField.length,
          })
        : !(source?.v && typeof source.v === 'object') && range
          ? sourceSegment(
              source,
              input,
              range[0],
              range[1],
              `request.${field}`,
              location,
              state,
              valueForField.length
            )
          : [];
      if (fieldMarks.length) state.putField(value, field, fieldMarks);
    }
  }
  return full;
}

function encodingAfter(value, args, _receiver, location, state) {
  if (!isString(value)) return [];
  return converted(state, marks(args[0]), value, 'url.encoding', location);
}

function registerStringAndArray() {
  register(String.prototype.slice, { after: stringSliceAfter('slice') });
  register(String.prototype.substring, {
    after: stringSliceAfter('substring'),
  });
  register(String.prototype.substr, { after: stringSliceAfter('substr') });
  register(String.prototype.concat, { after: stringConcatAfter });
  register(Array.prototype.join, { after: arrayJoinAfter });
}

function registerConversionAndBufferBuiltins() {
  if (typeof globalThis.String === 'function')
    register(globalThis.String, {
      after: primitiveConversionAfter('string.convert'),
    });
  if (typeof globalThis.Number === 'function')
    register(globalThis.Number, {
      after: primitiveConversionAfter('number.convert'),
    });
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function')
    register(Buffer.from, { after: bufferFromAfter });
  if (
    typeof Buffer !== 'undefined' &&
    typeof Buffer.prototype?.toString === 'function'
  )
    register(Buffer.prototype.toString, { after: bufferToStringAfter });
}

function registerPathBuiltins() {
  for (const root of [path, path.posix, path.win32]) {
    for (const name of ['join', 'resolve', 'normalize']) {
      if (typeof root?.[name] === 'function')
        register(root[name], { after: pathAfter(`path.${name}`) });
    }
  }
}

function registerUrlBuiltins() {
  if (typeof globalThis.URL === 'function') {
    register(globalThis.URL, { after: urlConstructorAfter });
    register(globalThis.URL.prototype?.toString, { after: urlToStringAfter });
  }
  if (typeof globalThis.URLSearchParams === 'function') {
    register(globalThis.URLSearchParams, { after: urlSearchParamsAfter });
    for (const name of ['toString', 'get', 'getAll', 'has'])
      register(globalThis.URLSearchParams.prototype?.[name], {
        after: urlSearchParamsMethodAfter,
      });
  }
  if (typeof globalThis.Request === 'function')
    register(globalThis.Request, { after: requestAfter });
  for (const name of [
    'encodeURI',
    'encodeURIComponent',
    'decodeURI',
    'decodeURIComponent',
  ]) {
    if (typeof globalThis[name] === 'function')
      register(globalThis[name], { after: encodingAfter });
  }
}

/** Install deterministic, identity-based propagation models for built-ins. */
export function installBuiltins() {
  if (builtinsInstalled) return;
  builtinsInstalled = true;
  registerStringAndArray();
  registerConversionAndBufferBuiltins();
  registerPathBuiltins();
  registerUrlBuiltins();
}

export { register as registerModel, urlFieldRange };

export default { installBuiltins };
