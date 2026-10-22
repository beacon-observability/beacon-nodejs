import { fileURLToPath } from 'node:url';
import { types } from 'node:util';

const NativeError = Error;
let captureStack;
try {
  const descriptor = Object.getOwnPropertyDescriptor(
    NativeError,
    'captureStackTrace'
  );
  if (
    typeof descriptor?.value === 'function' &&
    Function.prototype.toString.call(descriptor.value).includes('[native code]')
  )
    captureStack = descriptor.value;
} catch {
  /* An application-owned Error proxy remains outside this model. */
}
const ownDirectory = fileURLToPath(new URL('../', import.meta.url));
const ownUrl = new URL('../', import.meta.url).href;
const prepared = new WeakSet();
const initialFormatter = Object.getOwnPropertyDescriptor(
  NativeError,
  'prepareStackTrace'
)?.value;
// Node installs its own default formatter on some supported releases. It is
// not an application hook; retain its identity without replacing it globally.
const nodeFormatter =
  typeof initialFormatter === 'function' &&
  /^function ErrorPrepareStackTrace\(error, trace\) \{\s*return internalPrepareStackTrace\(error, trace\);\s*\}$/.test(
    Function.prototype.toString.call(initialFormatter)
  )
    ? initialFormatter
    : undefined;
const applicationFormatsStack = () => {
  const descriptor = Object.getOwnPropertyDescriptor(
    NativeError,
    'prepareStackTrace'
  );
  return (
    descriptor &&
    (!('value' in descriptor) ||
      (descriptor.value != null && descriptor.value !== nodeFormatter))
  );
};
const internal = line => line.includes(ownDirectory) || line.includes(ownUrl);

// Capture additional caller frames only when an Error crosses a helper. This
// avoids changing the global stack limit on every successful business call or
// installing a global prepareStackTrace hook owned by the application.
export function preserveErrorStack(error, boundary, depth) {
  try {
    if (
      !captureStack ||
      !types.isNativeError(error) ||
      prepared.has(error) ||
      applicationFormatsStack()
    )
      return;
    // Formatting a user-defined name/message accessor would introduce an
    // observable side effect. Leave those errors under application control.
    for (const key of ['name', 'message']) {
      let object = error;
      for (
        let i = 0;
        object && i < 16;
        i++, object = Object.getPrototypeOf(object)
      ) {
        if (types.isProxy(object)) return;
        const descriptor = Object.getOwnPropertyDescriptor(object, key);
        if (descriptor) {
          if (!('value' in descriptor)) return;
          if (
            descriptor.value !== null &&
            ['object', 'function'].includes(typeof descriptor.value)
          )
            return;
          break;
        }
      }
    }
    const setting = Object.getOwnPropertyDescriptor(
      NativeError,
      'stackTraceLimit'
    );
    if (!setting || !('value' in setting) || !setting.writable) return;
    const limit = setting.value;
    if (typeof limit !== 'number' || limit <= 0) return;
    const callers = {};
    try {
      if (Number.isFinite(limit))
        NativeError.stackTraceLimit = Math.max(
          limit,
          Math.min(4096, limit + 4 * (depth + 1))
        );
      Reflect.apply(captureStack, NativeError, [callers, boundary]);
    } finally {
      NativeError.stackTraceLimit = limit;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, 'stack');
    if (!descriptor?.configurable) return;
    prepared.add(error);
    const parse = stack => {
      const lines = stack.split('\n');
      const start = lines.findIndex(line => /^\s+at /.test(line));
      if (start < 0) return { header: stack, frames: [] };
      return {
        header: lines.slice(0, start).join('\n'),
        frames: lines.slice(start).filter(line => !internal(line)),
      };
    };
    const read = receiver => {
      const original = descriptor.get
        ? Reflect.apply(descriptor.get, receiver, [])
        : descriptor.value;
      if (
        applicationFormatsStack() ||
        typeof original !== 'string' ||
        !internal(original)
      )
        return original;
      const { header, frames } = parse(original);
      const extra = parse(callers.stack).frames;
      const overlap = frames.indexOf(extra[0]);
      const combined =
        overlap >= 0
          ? [...frames.slice(0, overlap), ...extra]
          : [...frames, ...extra];
      return [header, ...combined.slice(0, limit)].join('\n');
    };
    Object.defineProperty(error, 'stack', {
      configurable: true,
      enumerable: descriptor.enumerable,
      get() {
        const value = read(this);
        Object.defineProperty(this, 'stack', {
          value,
          configurable: true,
          writable: true,
          enumerable: descriptor.enumerable,
        });
        return value;
      },
      set(value) {
        Object.defineProperty(this, 'stack', {
          value,
          configurable: true,
          writable: true,
          enumerable: descriptor.enumerable,
        });
      },
    });
  } catch {
    // Stack diagnostics must never change the business exception.
  }
}
