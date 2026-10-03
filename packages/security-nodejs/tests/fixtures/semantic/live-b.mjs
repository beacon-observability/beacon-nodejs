import { liveValue } from './live-a.mjs';

export const bValue = 'b-stable';

export function getBValue() {
  return `b-sees:${liveValue}`;
}
