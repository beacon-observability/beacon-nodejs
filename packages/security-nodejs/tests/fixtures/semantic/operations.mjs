import { readCycle, updateLiveValue } from './live-a.mjs';

export class SemanticOriginalError extends Error {
  constructor() {
    super('semantic-original-error');
    this.name = 'SemanticOriginalError';
  }
}

export function recursiveClosure(value) {
  function factorial(n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
  }

  return factorial(value);
}

export function getterAndAssignment() {
  let getterCalls = 0;
  const source = {
    get value() {
      getterCalls += 1;
      return 'getter-value';
    },
  };
  const first = source.value;
  let assigned = 'before';
  assigned = first;
  const { value: destructured } = { value: assigned };
  return { first, destructured, assigned, getterCalls };
}

export function shortCircuitAndException() {
  const shortCircuit = false && 'must-not-evaluate';
  let exception;
  try {
    throw new SemanticOriginalError();
  } catch (error) {
    exception = { name: error.name, message: error.message };
  }
  return { shortCircuit, exception };
}

export async function promiseIsolation(requestId) {
  const values = await Promise.all([
    Promise.resolve(`${requestId}:a`),
    new Promise(resolve => setImmediate(() => resolve(`${requestId}:b`))),
  ]);
  return { requestId, values };
}

export async function runSemanticScenario(requestId) {
  const constant = 'same-value-constant';
  updateLiveValue('a-initial');
  const liveBindingBefore = readCycle();
  updateLiveValue('a-updated');
  const liveBindingAfter = readCycle();
  const [first, second] = await Promise.all([
    promiseIsolation(requestId),
    promiseIsolation(`${requestId}-parallel`),
  ]);
  return {
    constant,
    liveBindingCycle: { before: liveBindingBefore, after: liveBindingAfter },
    recursive: recursiveClosure(5),
    getter: getterAndAssignment(),
    shortCircuit: shortCircuitAndException(),
    concurrent: [first, second],
  };
}

export function assertSemanticResult(value, requestId) {
  const expected = {
    constant: 'same-value-constant',
    liveBindingCycle: {
      before: { a: 'a-initial', b: 'b-stable', fromB: 'b-sees:a-initial' },
      after: { a: 'a-updated', b: 'b-stable', fromB: 'b-sees:a-updated' },
    },
    recursive: 120,
    getter: {
      first: 'getter-value',
      destructured: 'getter-value',
      assigned: 'getter-value',
      getterCalls: 1,
    },
    shortCircuit: {
      shortCircuit: false,
      exception: {
        name: 'SemanticOriginalError',
        message: 'semantic-original-error',
      },
    },
    concurrent: [
      { requestId, values: [`${requestId}:a`, `${requestId}:b`] },
      {
        requestId: `${requestId}-parallel`,
        values: [`${requestId}-parallel:a`, `${requestId}-parallel:b`],
      },
    ],
  };
  return JSON.stringify(value) === JSON.stringify(expected);
}
