import { bValue, getBValue } from './live-b.mjs';

export let liveValue = 'a-initial';

export function updateLiveValue(value) {
  liveValue = value;
}

export function readCycle() {
  return { a: liveValue, b: bValue, fromB: getBValue() };
}
