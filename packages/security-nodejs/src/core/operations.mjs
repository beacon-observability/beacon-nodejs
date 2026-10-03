import { current } from './runtime.mjs';
import { p } from './values.mjs';

const primitive = v =>
  v === null || !['object', 'function', 'symbol'].includes(typeof v);
export function binary(op, a, b, location = '') {
  let value;
  switch (op) {
    case '+':
      value = a.v + b.v;
      break;
    case '-':
      value = a.v - b.v;
      break;
    case '*':
      value = a.v * b.v;
      break;
    case '/':
      value = a.v / b.v;
      break;
    case '%':
      value = a.v % b.v;
      break;
    case '**':
      value = a.v ** b.v;
      break;
    case '|':
      value = a.v | b.v;
      break;
    case '&':
      value = a.v & b.v;
      break;
    case '^':
      value = a.v ^ b.v;
      break;
    case '<<':
      value = a.v << b.v;
      break;
    case '>>':
      value = a.v >> b.v;
      break;
    case '>>>':
      value = a.v >>> b.v;
      break;
    case '==':
      value = a.v == b.v;
      break;
    case '!=':
      value = a.v != b.v;
      break;
    case '===':
      value = a.v === b.v;
      break;
    case '!==':
      value = a.v !== b.v;
      break;
    case '<':
      value = a.v < b.v;
      break;
    case '<=':
      value = a.v <= b.v;
      break;
    case '>':
      value = a.v > b.v;
      break;
    case '>=':
      value = a.v >= b.v;
      break;
    case 'in':
      value = a.v in b.v;
      break;
    case 'instanceof':
      value = a.v instanceof b.v;
      break;
    default:
      throw new Error('Unsupported transformed binary operator');
  }
  const state = current();
  if (!state || (!a.m.length && !b.m.length) || typeof value === 'boolean')
    return p(value);
  if (
    op === '+' &&
    typeof value === 'string' &&
    primitive(a.v) &&
    primitive(b.v)
  ) {
    const left = String(a.v).length;
    const am =
      typeof a.v === 'string'
        ? state.step(a.m, 'string.concat', location)
        : state.convert(a.m, String(a.v), 'string.conversion', location);
    const bm =
      typeof b.v === 'string'
        ? state.step(b.m, 'string.concat', location, { offset: left })
        : state.step(
            state.convert(b.m, String(b.v), 'string.conversion', location),
            'string.concat',
            location,
            { offset: left }
          );
    return p(value, [...am, ...bm]);
  }
  return p(
    value,
    state.convert([...a.m, ...b.m], value, 'binary.' + op, location)
  );
}
export function unary(op, a, location = '') {
  let value;
  switch (op) {
    case '+':
      value = +a.v;
      break;
    case '-':
      value = -a.v;
      break;
    case '~':
      value = ~a.v;
      break;
    case '!':
      value = !a.v;
      break;
    case 'void':
      value = void a.v;
      break;
    case 'typeof':
      value = typeof a.v;
      break;
    default:
      throw new Error('Unsupported transformed unary operator');
  }
  return p(
    value,
    ['+', '-', '~'].includes(op)
      ? current()?.convert(a.m, value, 'unary.' + op, location)
      : []
  );
}
export function updateValue(pair, increment, location = '') {
  let value = pair.v;
  const before = increment ? value++ : value--;
  const state = current();
  if (pair.v !== null && ['object', 'function'].includes(typeof pair.v))
    state?.gap('numeric_object_coercion');
  return {
    before: p(
      before,
      state?.convert(pair.m, before, 'numeric.update', location)
    ),
    after: p(value, state?.convert(pair.m, value, 'numeric.update', location)),
  };
}
export function string(pair, location = '') {
  // Template substitution uses ToString, which rejects Symbols even though String(symbol) accepts them.
  const value = `${pair.v}`;
  return p(
    value,
    typeof pair.v === 'string'
      ? pair.m
      : current()?.convert(pair.m, value, 'template.conversion', location)
  );
}
export function template(parts, location = '') {
  let value = '',
    marks = [];
  const state = current();
  for (const part of parts) {
    if (typeof part === 'string') value += part;
    else {
      if (state)
        marks.push(
          ...state.step(part.m, 'template.join', location, {
            offset: value.length,
          })
        );
      value += part.v;
    }
  }
  return p(value, marks);
}
