import http from 'node:http';
import { writeFile, readFile } from 'node:fs/promises';
import { shutdown } from '@beacon-observability/security-nodejs';
import express from 'express';

const path = '/tmp/security-node-collector-flow.txt';
await writeFile(path, 'collector-flow\n', 'utf8');
const app = express();
app.get('/flow', async (request, response, next) => {
  try {
    // The request query is the real source; the transformed module calls the
    // actual fs sink and the security exporter emits the observed event.
    const value = await readFile(request.query.path, 'utf8');
    response.json({ value });
  } catch (error) {
    next(error);
  }
});
const server = await new Promise((resolve, reject) => {
  const candidate = app.listen(0, '127.0.0.1', () => resolve(candidate));
  candidate.once('error', reject);
});
const port = server.address().port;
const response = await fetch(
  `http://127.0.0.1:${port}/flow?path=${encodeURIComponent(path)}`
);
const body = await response.json();
if (response.status !== 200 || body.value !== 'collector-flow\n')
  throw new Error(`flow_response:${response.status}`);
await shutdown({ timeoutMillis: 2_000 });
await globalThis.__securityQaFlushLogs?.();
await new Promise(resolve => server.close(resolve));
let health;
try {
  health = JSON.parse(
    await readFile(`${process.env.BEACON_SECURITY_OUTPUT}/health.json`, 'utf8')
  );
} catch {
  health = null;
}
process.stdout.write(
  JSON.stringify({
    status: 'sent',
    traceRequired: true,
    body,
    counts: health?.counts || null,
    delivery: health?.delivery || null,
  }) + '\n'
);
