import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = mkdtempSync(join(tmpdir(), 'BeaconSecurity-reclaim-'));
const fixtureFile = join(root, 'payload.txt');
writeFileSync(fixtureFile, 'security-reclaim-ok\n', 'utf8');

function ready(value) {
  process.stdout.write(`BEACON_SECURITY_QA_READY ${JSON.stringify(value)}\n`);
}

const expressModule = await import('express');
const express = expressModule.default || expressModule;
const app = express();
app.get('/flow', (req, res, next) => {
  try {
    const requested = String(req.query.path || '');
    const selected = requested.slice(0, 1024).concat('');
    const body = readFileSync(selected, 'utf8');
    res.type('text/plain').send(body);
  } catch (error) {
    next(error);
  }
});
app.get('/__qa/metrics', (_req, res) =>
  res.json(
    globalThis.__securityQaSoakSnapshot?.() || { error: 'snapshot_unavailable' }
  )
);
app.use((error, _req, res, _next) =>
  res.status(500).json({ error: error.message })
);

const server = await new Promise((resolve, reject) => {
  const value = app.listen(0, '127.0.0.1', () => resolve(value));
  value.once('error', reject);
});
ready({ port: server.address().port, fixtureFile });

async function shutdown() {
  try {
    await globalThis.__securityQaSoakShutdown?.();
  } finally {
    server.closeIdleConnections?.();
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(() => resolve()));
  }
}
process.once('SIGTERM', () =>
  shutdown().then(
    () => process.exit(0),
    error => {
      process.stderr.write(
        `BEACON_SECURITY_QA_SHUTDOWN_ERROR ${error.stack || error}\n`
      );
      process.exit(1);
    }
  )
);
process.once('SIGINT', () =>
  shutdown().then(
    () => process.exit(0),
    () => process.exit(1)
  )
);
