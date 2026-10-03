import { createRequire } from 'node:module';
import { types } from 'node:util';
import {
  installBuiltins as installModelBuiltins,
  registerModel,
  urlFieldRange,
} from './models.mjs';

const require = createRequire(import.meta.url);
let builtinsInstalled = false;

function bounded(value, length = 512) {
  if (value === undefined || value === null) return '';
  try {
    return String(value).slice(0, length);
  } catch {
    return '';
  }
}

function pairMarks(pair) {
  return Array.isArray(pair?.m) ? pair.m : [];
}

function sink(state, rule, role, name, location, marks) {
  // SecurityState records the observed sink site even when the current call
  // carries no taint; it filters clean marks and disabled rules itself.
  state.sink(rule, role, name, location, marks || []);
}

function fieldMarks(state, value, key) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function'))
    return [];
  return state.field(value, key);
}

function isModuleNamespaceProxy(value) {
  if (!types.isProxy(value)) return false;
  try {
    // import-in-the-middle exposes a live ESM namespace through this proxy.
    // It is the only proxy we inspect while installing a library; request,
    // options, and argv proxies remain opaque below.
    return Reflect.get(value, Symbol.toStringTag) === 'Module';
  } catch {
    return false;
  }
}

function ownDescriptor(value, key) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function'))
    return { present: false, unknown: false };
  if (types.isProxy(value) && !isModuleNamespaceProxy(value))
    return { present: false, unknown: true };
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor) return { present: false, unknown: false };
    if (!('value' in descriptor)) return { present: true, unknown: true };
    return { present: true, unknown: false, value: descriptor.value };
  } catch {
    return { present: true, unknown: true };
  }
}

function ownValue(value, key) {
  const descriptor = ownDescriptor(value, key);
  return descriptor.present && !descriptor.unknown
    ? descriptor.value
    : undefined;
}

function knownValue(value, key) {
  if (types.isProxy(value)) return undefined;
  const own = ownValue(value, key);
  if (own !== undefined) return own;
  if (
    typeof globalThis.Request === 'function' &&
    value instanceof globalThis.Request &&
    key === 'url'
  ) {
    try {
      return value.url;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function valuesOf(exportsValue) {
  const values = [];
  const seen = new Set();
  const visit = (value, depth = 0) => {
    if (
      depth > 2 ||
      !value ||
      (typeof value !== 'object' && typeof value !== 'function') ||
      seen.has(value)
    )
      return;
    seen.add(value);
    values.push(value);
    const defaultValue = ownValue(value, 'default');
    if (defaultValue) visit(defaultValue, depth + 1);
  };
  visit(exportsValue);
  return values;
}

function inheritedValue(value, key) {
  if (types.isProxy(value)) return undefined;
  let current = value;
  for (let depth = 0; current && depth < 8; depth += 1) {
    const candidate = ownValue(current, key);
    if (candidate !== undefined) return candidate;
    try {
      current = Object.getPrototypeOf(current);
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function prototypeMethods(value, names, handlerFactory, prefix) {
  for (const root of valuesOf(value)) {
    const prototypes = [];
    if (typeof root === 'function' && root.prototype)
      prototypes.push(root.prototype);
    if (root && typeof root === 'object') {
      for (const key of Object.keys(root).slice(0, 128)) {
        const item = ownValue(root, key);
        if (typeof item === 'function' && item.prototype)
          prototypes.push(item.prototype);
        else if (item && typeof item === 'object') prototypes.push(item);
      }
    }
    const seen = new Set();
    for (const prototype of prototypes) {
      if (!prototype || seen.has(prototype)) continue;
      seen.add(prototype);
      for (const name of names) {
        const fn = inheritedValue(prototype, name);
        if (typeof fn === 'function')
          registerModel(fn, handlerFactory(`${prefix}.${name}`));
      }
    }
  }
}

function queryTemplateMarks(args, state, field) {
  const first = args[0];
  if (!first) return [];
  if (typeof first.v === 'string' || Buffer.isBuffer(first.v))
    return pairMarks(first);
  if (first.v && typeof first.v === 'object') {
    // Driver config objects have one field that represents the SQL text.
    // Marks on values, query metadata, or the carrier object itself do not
    // prove that the statement text is tainted.
    return state.valid(field ? fieldMarks(state, first.v, field) : []);
  }
  return [];
}

function sqlHandler(name) {
  const sqlField = name.startsWith('pg.') ? 'text' : 'sql';
  return {
    before(args, _receiver, location, state) {
      sink(
        state,
        'sql_injection',
        'template',
        name,
        location,
        queryTemplateMarks(args, state, sqlField)
      );
    },
  };
}

function installSql(name, exportsValue) {
  if (name === 'pg') {
    prototypeMethods(exportsValue, ['query'], sqlHandler, 'pg');
  } else if (name === 'mysql2' || name === 'mysql2/promise') {
    prototypeMethods(exportsValue, ['query', 'execute'], sqlHandler, 'mysql2');
  }
}

function arrayMarks(value, state) {
  if (!Array.isArray(value?.v)) return [];
  if (types.isProxy(value.v)) {
    state.gap('child_process.argv_proxy');
    return pairMarks(value);
  }
  const result = [];
  for (let index = 0; index < Math.min(value.v.length, 4096); index += 1) {
    result.push(...state.field(value.v, String(index)));
  }
  return state.valid(result.length ? result : pairMarks(value));
}

function explicitShellScript(executablePair, argvPair, state) {
  const executable = executablePair?.v;
  if (typeof executable !== 'string' || !Array.isArray(argvPair?.v))
    return null;
  if (types.isProxy(argvPair.v)) {
    state.gap('child_process.argv_proxy');
    return { recognized: true, unknown: true, marks: pairMarks(argvPair) };
  }
  const basename =
    executable.replaceAll('\\', '/').split('/').at(-1)?.toLowerCase() || '';
  const windows = ['cmd.exe', 'powershell.exe', 'pwsh.exe'].includes(basename);
  const posix = ['sh', 'bash', 'dash', 'zsh', 'ksh', 'fish', 'ash'].includes(
    basename
  );
  if (!windows && !posix) return null;
  if (windows) state.gap('child_process.windows_shell_boundary');
  const flags = windows
    ? new Set(['/c', '/k', '-c', '--command', '-command'])
    : new Set(['-c', '--command']);
  const limit = Math.min(argvPair.v.length, 4096);
  let scriptIndex = -1;
  for (let index = 0; index < limit; index += 1) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(argvPair.v, String(index));
    } catch {
      state.gap('child_process.argv_descriptor');
      return { recognized: true, unknown: true, marks: pairMarks(argvPair) };
    }
    if (descriptor && !('value' in descriptor)) {
      state.gap('child_process.argv_accessor');
      return { recognized: true, unknown: true, marks: pairMarks(argvPair) };
    }
    if (flags.has(descriptor?.value)) {
      scriptIndex = index + 1;
      break;
    }
  }
  if (scriptIndex < 0) return { recognized: false, marks: [] };
  if (scriptIndex >= limit) {
    state.gap('child_process.shell_script_missing');
    return { recognized: true, marks: [] };
  }
  const marks = state.field(argvPair.v, String(scriptIndex));
  return {
    recognized: true,
    marks: marks.length ? marks : pairMarks(argvPair),
  };
}

function shellEnabled(pair, state) {
  if (!pair?.v || typeof pair.v !== 'object') return false;
  if (types.isProxy(pair.v)) {
    state.gap('child_process.option_accessor');
    return undefined;
  }
  // Do not invoke an application getter while observing options before the
  // real child_process call.  The native function remains the only reader.
  let current = pair.v;
  for (let depth = 0; current && depth < 8; depth += 1) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(current, 'shell');
    } catch {
      return undefined;
    }
    if (descriptor) {
      if (!('value' in descriptor)) {
        state.gap('child_process.option_accessor');
        return undefined;
      }
      return Boolean(descriptor.value);
    }
    try {
      current = Object.getPrototypeOf(current);
    } catch {
      return undefined;
    }
  }
  return false;
}

function childProcessHandler(name) {
  const fileCall = name.endsWith('File') || name.endsWith('FileSync');
  const spawnCall = name.startsWith('spawn');
  const execCall = name.startsWith('exec') && !fileCall;
  return {
    // util.promisify(exec/execFile) preserves the callback API's argument
    // contract.  spawn and synchronous variants have no standard callback
    // promisifier and must not be inherited by a derived function.
    promisify: name === 'exec' || name === 'execFile',
    before(args, _receiver, location, state) {
      if (execCall) {
        sink(
          state,
          'command_injection',
          'shell',
          `child_process.${name}`,
          location,
          pairMarks(args[0])
        );
        return;
      }
      if (!fileCall && !spawnCall) return;
      const optionIndex =
        args[1]?.v && typeof args[1].v === 'object' && !Array.isArray(args[1].v)
          ? 1
          : 2;
      const options = args[optionIndex];
      const executable = pairMarks(args[0]);
      const argv = optionIndex === 1 ? [] : arrayMarks(args[1], state);
      const shell = shellEnabled(options, state);
      if (shell === undefined) {
        // The option getter was intentionally not invoked.  Preserve the
        // call as a conservative observation under either possible mode.
        sink(
          state,
          'command_execution',
          'executable',
          `child_process.${name}`,
          location,
          executable
        );
        sink(
          state,
          'command_execution',
          'argv',
          `child_process.${name}`,
          location,
          argv
        );
        sink(
          state,
          'command_injection',
          'shell',
          `child_process.${name}`,
          location,
          state.valid([...executable, ...argv])
        );
        return;
      }
      if (shell) {
        sink(
          state,
          'command_injection',
          'shell',
          `child_process.${name}`,
          location,
          state.valid([...executable, ...argv])
        );
      } else {
        sink(
          state,
          'command_execution',
          'executable',
          `child_process.${name}`,
          location,
          executable
        );
        sink(
          state,
          'command_execution',
          'argv',
          `child_process.${name}`,
          location,
          argv
        );
        const explicit = explicitShellScript(args[0], args[1], state);
        if (explicit?.recognized) {
          const scriptMarks = explicit.unknown
            ? state.valid([...executable, ...argv])
            : explicit.marks;
          sink(
            state,
            'command_injection',
            'shell',
            `child_process.${name}`,
            location,
            scriptMarks
          );
        }
      }
    },
  };
}

function installChildProcess(exportsValue) {
  for (const root of valuesOf(exportsValue)) {
    for (const name of [
      'exec',
      'execSync',
      'execFile',
      'execFileSync',
      'spawn',
      'spawnSync',
    ]) {
      const fn = ownValue(root, name);
      if (typeof fn === 'function')
        registerModel(fn, childProcessHandler(name));
    }
  }
}

function textFromTarget(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && types.isProxy(value)) return '';
  if (value instanceof URL) return value.href;
  if (value && typeof value === 'object') {
    const url = knownValue(value, 'url');
    if (typeof url === 'string') return url;
    const href = knownValue(value, 'href');
    if (typeof href === 'string') return href;
    const protocolValue = ownValue(value, 'protocol');
    const hostnameValue = ownValue(value, 'hostname');
    const hostValue = ownValue(value, 'host');
    const portValue = ownValue(value, 'port');
    const pathValue = ownValue(value, 'path');
    const pathnameValue = ownValue(value, 'pathname');
    const protocol = typeof protocolValue === 'string' ? protocolValue : '';
    const host =
      typeof hostnameValue === 'string'
        ? hostnameValue
        : typeof hostValue === 'string'
          ? hostValue
          : '';
    const port =
      typeof portValue === 'string' || typeof portValue === 'number'
        ? `:${portValue}`
        : '';
    const requestPath =
      typeof pathValue === 'string'
        ? pathValue
        : typeof pathnameValue === 'string'
          ? pathnameValue
          : '/';
    if (host) return `${protocol || 'http:'}//${host}${port}${requestPath}`;
  }
  return '';
}

function segmentMarks(pair, text, field, operation, location, state) {
  if (!pairMarks(pair).length) return [];
  const range = urlFieldRange(text, field);
  if (!range) return [];
  return state.step(pairMarks(pair), operation, location, {
    from: range[0],
    to: range[1],
    offset: -range[0],
    length: range[1] - range[0],
  });
}

function fieldSegmentMarks(
  field,
  text,
  start,
  end,
  operation,
  location,
  state
) {
  if (!field.length || start < 0 || end <= start) return [];
  return state.step(field, operation, location, {
    from: start,
    to: end,
    offset: -start,
    length: end - start,
  });
}

function appendField(
  result,
  bucket,
  field,
  rawValue,
  operation,
  location,
  state
) {
  if (!field.length) return;
  if (typeof rawValue !== 'string' || !rawValue) {
    result[bucket].push(...field);
    return;
  }
  if (
    bucket === 'path' &&
    (operation.endsWith('.path') || operation.endsWith('.pathname'))
  ) {
    const queryStart = rawValue.indexOf('?');
    const pathEnd = queryStart >= 0 ? queryStart : rawValue.length;
    result.path.push(
      ...fieldSegmentMarks(
        field,
        rawValue,
        0,
        pathEnd,
        operation,
        location,
        state
      )
    );
    if (queryStart >= 0)
      result.query.push(
        ...fieldSegmentMarks(
          field,
          rawValue,
          queryStart,
          rawValue.length,
          operation.replace(/\.path(?:name)?$/, '.query'),
          location,
          state
        )
      );
    return;
  }
  result[bucket].push(...field);
}

function appendUrlField(result, field, urlValue, location, state) {
  if (!field.length || typeof urlValue !== 'string' || !urlValue) return;
  try {
    const parsed = new URL(urlValue, 'http://beacon.security.invalid');
    if (parsed.host !== 'beacon.security.invalid') {
      const range = urlFieldRange(urlValue, 'host');
      if (range)
        result.host.push(
          ...fieldSegmentMarks(
            field,
            urlValue,
            range[0],
            range[1],
            'url.host',
            location,
            state
          )
        );
    }
    const pathRange = urlFieldRange(urlValue, 'pathname');
    if (pathRange)
      result.path.push(
        ...fieldSegmentMarks(
          field,
          urlValue,
          pathRange[0],
          pathRange[1],
          'url.path',
          location,
          state
        )
      );
    if (parsed.search) {
      const queryRange = urlFieldRange(urlValue, 'search');
      if (queryRange)
        result.query.push(
          ...fieldSegmentMarks(
            field,
            urlValue,
            queryRange[0],
            queryRange[1],
            'url.query',
            location,
            state
          )
        );
    }
  } catch {
    result.any.push(...field);
  }
}

function optionOverrides(value, state, location) {
  const result = {
    host: false,
    path: false,
    unknown: false,
    hostMarks: [],
    pathMarks: [],
    queryMarks: [],
    anyMarks: [],
  };
  if (!value || typeof value !== 'object') return result;
  if (types.isProxy(value)) {
    state.gap('http.options_proxy');
    result.unknown = true;
    return result;
  }
  if (value instanceof URL) return result;
  const hostKeys = ['hostname', 'host', 'port'];
  for (const key of hostKeys) {
    const property = ownDescriptor(value, key);
    if (!property.present) continue;
    result.host = true;
    if (property.unknown) {
      state.gap('http.options_accessor');
      result.unknown = true;
      continue;
    }
    result.hostMarks.push(...fieldMarks(state, value, key));
  }
  const pathProperty = ownDescriptor(value, 'path');
  if (pathProperty.present) {
    result.path = true;
    if (pathProperty.unknown) {
      state.gap('http.options_accessor');
      result.unknown = true;
    } else {
      const pathField = fieldMarks(state, value, 'path');
      const pathParts = { path: [], query: [] };
      appendField(
        pathParts,
        'path',
        pathField,
        pathProperty.value,
        'options.path',
        location,
        state
      );
      result.pathMarks.push(...pathParts.path);
      result.queryMarks.push(...pathParts.query);
    }
  }
  return result;
}

function targetParts(pair, state, location) {
  const result = { any: [], host: [], path: [], query: [] };
  if (!pair) return result;
  const value = pair.v;
  const proxy = value && typeof value === 'object' && types.isProxy(value);
  const urlObject = !proxy && value instanceof URL;
  const text = textFromTarget(value);
  const objectValue = value && typeof value === 'object' && !urlObject;
  if (objectValue) {
    if (proxy) {
      state.gap('http.target_proxy');
      result.any.push(...pairMarks(pair));
      result.any = state.valid(result.any);
      return result;
    }
    const pathname = ownValue(value, 'pathname');
    const path = ownValue(value, 'path');
    result.host.push(
      ...fieldMarks(state, value, 'hostname'),
      ...fieldMarks(state, value, 'host')
    );
    appendField(
      result,
      'path',
      fieldMarks(state, value, 'pathname'),
      pathname,
      'options.pathname',
      location,
      state
    );
    appendField(
      result,
      'path',
      fieldMarks(state, value, 'path'),
      path,
      'options.path',
      location,
      state
    );
    result.query.push(
      ...fieldMarks(state, value, 'search'),
      ...fieldMarks(state, value, 'query')
    );
    if (state.record(value)?.data?.componentTracked !== true)
      result.any.push(...pairMarks(pair));
    const urlField = fieldMarks(state, value, 'url').concat(
      fieldMarks(state, value, 'href')
    );
    const urlCandidate = knownValue(value, 'url');
    const hrefCandidate = knownValue(value, 'href');
    const urlValue =
      typeof urlCandidate === 'string'
        ? urlCandidate
        : typeof hrefCandidate === 'string'
          ? hrefCandidate
          : '';
    // Component marks are authoritative.  A whole-url mark is only a
    // fallback when no component has been proved, otherwise a query-only
    // input could be upgraded to host/path by lexical projection.
    if (
      state.record(value)?.data?.componentTracked !== true &&
      !result.host.length &&
      !result.path.length &&
      !result.query.length
    ) {
      appendUrlField(result, urlField, urlValue, location, state);
    }
  }
  if (urlObject) {
    result.host.push(
      ...fieldMarks(state, value, 'hostname'),
      ...fieldMarks(state, value, 'host')
    );
    appendField(
      result,
      'path',
      fieldMarks(state, value, 'pathname'),
      value.pathname,
      'url.pathname',
      location,
      state
    );
    appendField(
      result,
      'path',
      fieldMarks(state, value, 'path'),
      ownValue(value, 'path'),
      'url.path',
      location,
      state
    );
    result.query.push(
      ...fieldMarks(state, value, 'search'),
      ...fieldMarks(state, value, 'query')
    );
    if (state.record(value)?.data?.componentTracked !== true) {
      appendUrlField(
        result,
        fieldMarks(state, value, 'href'),
        value.href,
        location,
        state
      );
    }
    if (state.record(value)?.data?.componentTracked !== true)
      result.any.push(...pairMarks(pair));
  }
  if (text && !objectValue && !(value instanceof URL)) {
    try {
      const parsed = new URL(text, 'http://beacon.security.invalid');
      result.host.push(
        ...segmentMarks(pair, text, 'host', 'url.host', location, state)
      );
      result.path.push(
        ...segmentMarks(pair, text, 'pathname', 'url.path', location, state)
      );
      if (parsed.search)
        result.query.push(
          ...segmentMarks(pair, text, 'search', 'url.query', location, state)
        );
    } catch {
      result.any.push(...pairMarks(pair));
    }
  } else if (!objectValue && !(value instanceof URL)) {
    result.any.push(...pairMarks(pair));
  }
  for (const key of ['host', 'path', 'query'])
    result[key] = state.valid(result[key]);
  result.any = state.valid(result.any);
  return result;
}

function mergeHttpParts(first, second, overrides, state) {
  const result = { any: [], host: [], path: [], query: [] };
  if (overrides?.unknown) {
    // An options Proxy/accessor can replace the URL fields without exposing
    // their values. Keep only conservative unknown-target evidence.
    result.any.push(
      ...pairMarks(first),
      ...pairMarks(second),
      ...(overrides.anyMarks || [])
    );
    return result;
  }
  result.any.push(...first.any, ...second.any);
  result.host.push(
    ...(overrides?.host ? overrides.hostMarks : first.host),
    ...(!overrides?.host ? second.host : [])
  );
  result.path.push(
    ...(overrides?.path ? overrides.pathMarks : first.path),
    ...(!overrides?.path ? second.path : [])
  );
  result.query.push(
    ...(overrides?.path ? overrides.queryMarks : first.query),
    ...(!overrides?.path ? second.query : [])
  );
  return result;
}

function httpHandler(name) {
  return {
    before(args, _receiver, location, state) {
      const first = targetParts(args[0], state, location);
      const isFetch = name === 'fetch' || name.endsWith('.fetch');
      const second = isFetch
        ? { any: [], host: [], path: [], query: [] }
        : targetParts(args[1], state, location);
      const overrides = isFetch
        ? null
        : optionOverrides(args[1]?.v, state, location);
      const all = mergeHttpParts(first, second, overrides, state);
      all.host = state.valid(all.host);
      all.path = state.valid(all.path);
      all.query = state.valid(all.query);
      all.any = state.valid(all.any);
      // A real request reaches all three carrier boundaries even when the
      // current arguments are clean; SecurityState records those observations
      // separately from tainted findings.
      sink(state, 'ssrf', 'destination_address', name, location, all.host);
      sink(
        state,
        'http_request_input',
        'request_path',
        name,
        location,
        all.path
      );
      sink(
        state,
        'http_request_input',
        'request_query',
        name,
        location,
        all.query
      );
      if (
        !all.host.length &&
        !all.path.length &&
        !all.query.length &&
        all.any.length
      )
        sink(state, 'ssrf', 'unknown_target', name, location, all.any);
    },
  };
}

function installHttp(name, exportsValue) {
  for (const root of valuesOf(exportsValue)) {
    for (const method of ['request', 'get']) {
      const fn = ownValue(root, method);
      if (typeof fn === 'function')
        registerModel(fn, httpHandler(`${name}.${method}`));
    }
  }
}

function installFetch(name, exportsValue) {
  for (const root of valuesOf(exportsValue)) {
    const fn = ownValue(root, 'fetch');
    if (typeof fn === 'function')
      registerModel(fn, httpHandler(`${name}.fetch`));
    const request = ownValue(root, 'request');
    if (typeof request === 'function')
      registerModel(request, httpHandler(`${name}.request`));
  }
  if (name === 'undici' && typeof globalThis.fetch === 'function')
    registerModel(globalThis.fetch, httpHandler('fetch'));
}

function pathMarks(pair, state, key = '') {
  if (!pair) return [];
  if (pair.v && typeof pair.v === 'object' && types.isProxy(pair.v)) {
    state.gap('fs.path_proxy');
    return state.valid(pairMarks(pair));
  }
  const result = [...pairMarks(pair)];
  if (key && pair.v && typeof pair.v === 'object')
    result.push(...fieldMarks(state, pair.v, key));
  if (pair.v instanceof URL) {
    if (pair.v.protocol !== 'file:') {
      state.gap('fs.file_url_scheme');
      return [];
    }
    if (pair.v.host) {
      state.gap('fs.file_url_host_boundary');
      return [];
    }
    const tracked = state.record(pair.v)?.data?.componentTracked === true;
    if (tracked) {
      // fs ignores URL search/hash when resolving a file URL. A whole URL mark
      // would therefore turn query input into a path finding.
      return state.valid(fieldMarks(state, pair.v, 'pathname'));
    }
    const pathname = pair.v.href;
    const range = urlFieldRange(pathname, 'pathname');
    if (!range) {
      state.gap('fs.file_url_boundary');
      return [];
    }
    return state.valid(
      state.step(pairMarks(pair), 'url.pathname', '', {
        from: range[0],
        to: range[1],
        offset: -range[0],
        length: range[1] - range[0],
      })
    );
  }
  return state.valid(result);
}

const PROMISIFIABLE_FS_METHODS = new Set([
  'access',
  'appendFile',
  'chmod',
  'chown',
  'close',
  'copyFile',
  'cp',
  'fstat',
  'lstat',
  'link',
  'mkdir',
  'mkdtemp',
  'open',
  'opendir',
  'read',
  'readFile',
  'readdir',
  'readlink',
  'realpath',
  'rename',
  'rm',
  'rmdir',
  'stat',
  'statfs',
  'symlink',
  'truncate',
  'unlink',
  'utimes',
  'write',
  'writeFile',
]);

function fsHandler(name, promisifyHandler = false) {
  const baseName = name.endsWith('Sync') ? name.slice(0, -4) : name;
  const read = new Set([
    'access',
    'close',
    'lstat',
    'opendir',
    'open',
    'read',
    'readFile',
    'readdir',
    'readlink',
    'realpath',
    'stat',
    'statfs',
    'fstat',
    'exists',
  ]);
  const copy = new Set(['copyFile', 'cp', 'link']);
  const move = new Set(['rename']);
  const deleteMethods = new Set(['rm', 'rmdir', 'unlink']);
  const write = new Set([
    'appendFile',
    'chmod',
    'chown',
    'mkdir',
    'mkdtemp',
    'symlink',
    'truncate',
    'utimes',
    'write',
    'writeFile',
  ]);
  return {
    // Only node:fs callback functions with the documented callback shape are
    // safe to carry across util.promisify.  fs/promises and sync methods do
    // not satisfy that contract.
    promisify: promisifyHandler,
    before(args, _receiver, location, state) {
      if (copy.has(baseName)) {
        sink(
          state,
          'path_traversal',
          'source',
          `fs.${name}`,
          location,
          pathMarks(args[0], state)
        );
        sink(
          state,
          'path_traversal',
          'target',
          `fs.${name}`,
          location,
          pathMarks(args[1], state)
        );
      } else if (move.has(baseName)) {
        sink(
          state,
          'path_traversal',
          'source',
          `fs.${name}`,
          location,
          pathMarks(args[0], state)
        );
        sink(
          state,
          'path_traversal',
          'target',
          `fs.${name}`,
          location,
          pathMarks(args[1], state)
        );
      } else if (deleteMethods.has(baseName) || write.has(baseName)) {
        sink(
          state,
          'path_traversal',
          'target',
          `fs.${name}`,
          location,
          pathMarks(args[0], state)
        );
      } else if (baseName === 'open') {
        const flags = bounded(args[1]?.v, 64).toLowerCase();
        const target = /[wax+]/.test(flags) ? 'target' : 'source';
        sink(
          state,
          'path_traversal',
          target,
          `fs.${name}`,
          location,
          pathMarks(args[0], state)
        );
      } else if (read.has(baseName)) {
        sink(
          state,
          'path_traversal',
          'source',
          `fs.${name}`,
          location,
          pathMarks(args[0], state)
        );
      }
    },
  };
}

function installFs(name, exportsValue) {
  const methods = [
    'access',
    'accessSync',
    'appendFile',
    'appendFileSync',
    'chmod',
    'chmodSync',
    'chown',
    'chownSync',
    'close',
    'closeSync',
    'copyFile',
    'copyFileSync',
    'cp',
    'cpSync',
    'existsSync',
    'fstat',
    'fstatSync',
    'lstat',
    'lstatSync',
    'link',
    'linkSync',
    'mkdir',
    'mkdirSync',
    'mkdtemp',
    'mkdtempSync',
    'open',
    'openSync',
    'opendir',
    'opendirSync',
    'read',
    'readSync',
    'readFile',
    'readFileSync',
    'readdir',
    'readdirSync',
    'readlink',
    'readlinkSync',
    'realpath',
    'realpathSync',
    'rename',
    'renameSync',
    'rm',
    'rmSync',
    'rmdir',
    'rmdirSync',
    'stat',
    'statSync',
    'statfs',
    'statfsSync',
    'symlink',
    'symlinkSync',
    'truncate',
    'truncateSync',
    'unlink',
    'unlinkSync',
    'utimes',
    'utimesSync',
    'write',
    'writeSync',
    'writeFile',
    'writeFileSync',
  ];
  for (const root of valuesOf(exportsValue)) {
    for (const nameOfMethod of methods) {
      const fn = ownValue(root, nameOfMethod);
      if (typeof fn === 'function')
        registerModel(
          fn,
          fsHandler(
            nameOfMethod,
            name === 'fs' && PROMISIFIABLE_FS_METHODS.has(nameOfMethod)
          )
        );
    }
  }
}

/**
 * Register models for one loaded library. Re-registering a function is safe;
 * the identity map in calls.mjs makes installation idempotent and the
 * __original chain keeps OTel wrappers associated with their native function.
 */
export function installLibrary(name, exportsValue, _version = '') {
  const library = bounded(name, 256).replace(/^node:/, '');
  if (library === 'pg') installSql(library, exportsValue);
  else if (library === 'mysql2' || library === 'mysql2/promise')
    installSql(library, exportsValue);
  else if (library === 'child_process') installChildProcess(exportsValue);
  else if (library === 'http' || library === 'https')
    installHttp(library, exportsValue);
  else if (library === 'undici') installFetch(library, exportsValue);
  else if (library === 'fs' || library === 'fs/promises')
    installFs(library, exportsValue);
  // InstrumentationNodeModuleDefinition.patch must return the original export
  // object; the adapter only registers identity models on its functions.
  return exportsValue;
}

/** Install all built-in models and sink adapters once. */
export function installBuiltins() {
  if (builtinsInstalled) return;
  builtinsInstalled = true;
  installModelBuiltins();
  installLibrary('node:child_process', require('node:child_process'));
  const fs = require('node:fs');
  installLibrary('node:fs', fs);
  installLibrary('node:fs/promises', fs.promises);
  installLibrary('node:http', require('node:http'));
  installLibrary('node:https', require('node:https'));
  if (typeof globalThis.fetch === 'function')
    registerModel(globalThis.fetch, httpHandler('fetch'));
}

export default { installBuiltins, installLibrary };
