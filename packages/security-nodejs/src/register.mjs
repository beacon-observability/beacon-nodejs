import { isMainThread } from 'node:worker_threads';
if (isMainThread) {
  const { SecurityInstrumentation } = await import('./index.mjs');
  new SecurityInstrumentation();
}
