import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { resolve } from 'node:path';

const root = resolve(new URL('../..', import.meta.url).pathname);
const resultsDir = resolve(
  process.env.BEACON_SECURITY_QA_RESULTS_DIR ||
    '/tmp/beacon_security-nodejs-reclaim-results'
);
const requestCount = Number(
  process.env.BEACON_SECURITY_QA_RECLAIM_REQUESTS || 250
);
const concurrency = Number(
  process.env.BEACON_SECURITY_QA_RECLAIM_CONCURRENCY || 8
);
const securityOutput = resolve(
  process.env.BEACON_SECURITY_OUTPUT ||
    '/tmp/beacon_security-nodejs-reclaim-output'
);
const entry = resolve(root, 'tests/fixtures/matrix/app.mjs');
const businessRoots = [
  resolve(root, 'tests/fixtures/matrix'),
  resolve(root, 'tests/fixtures/semantic'),
].join(',');

function tagged(text, tag) {
  return text.split(/\r?\n/).flatMap(line => {
    if (!line.startsWith(`${tag} `)) return [];
    try {
      return [JSON.parse(line.slice(tag.length + 1))];
    } catch {
      return [];
    }
  });
}

function request(port, path, timeoutMillis = 10_000) {
  return new Promise((resolveRequest, reject) => {
    const value = httpRequest({ host: '127.0.0.1', port, path }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => {
        body += chunk;
      });
      response.on('end', () => {
        let parsed = null;
        try {
          parsed = JSON.parse(body);
        } catch {
          /* the status remains useful */
        }
        resolveRequest({ status: response.statusCode, value: parsed });
      });
    });
    const timer = setTimeout(
      () => value.destroy(new Error(`timeout:${path}`)),
      timeoutMillis
    );
    value.on('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    value.on('close', () => clearTimeout(timer));
    value.end();
  });
}

function waitForReady(child, timeoutMillis = 20_000) {
  return new Promise((resolveReady, reject) => {
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(
      () => reject(new Error(`startup_timeout:${stderr.slice(-500)}`)),
      timeoutMillis
    );
    child.stdout.on('data', chunk => {
      stdout += chunk;
      const ready = tagged(stdout, 'BEACON_SECURITY_QA_READY')[0];
      if (ready) {
        clearTimeout(timer);
        resolveReady({ ready });
      }
    });
    child.stderr.on('data', chunk => {
      stderr += chunk;
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      reject(new Error(`startup_exit:${code}:${signal}:${stderr.slice(-500)}`));
    });
  });
}

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null)
    return { bounded: true };
  const exited = once(child, 'exit').then(([code, signal]) => ({
    code,
    signal,
  }));
  child.kill('SIGTERM');
  const timeout = new Promise(resolveTimeout =>
    setTimeout(() => resolveTimeout({ timeout: true }), 5_000)
  );
  const outcome = await Promise.race([exited, timeout]);
  if (outcome.timeout) {
    child.kill('SIGKILL');
    await exited;
    return { bounded: false, forced: true };
  }
  return { bounded: true, ...outcome };
}

const startedAt = Date.now();
const env = {
  ...process.env,
  BEACON_SECURITY_ENABLED: 'true',
  BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'true',
  BEACON_SECURITY_SBOM_ENABLED: 'false',
  BEACON_SECURITY_NODE_INCLUDE: businessRoots,
  BEACON_SECURITY_OUTPUT: securityOutput,
  BEACON_SECURITY_QA_FRAMEWORK: 'express5',
  BEACON_SECURITY_QA_MODULE_SYSTEM: 'esm',
  NODE_OPTIONS: '',
};
const args = [
  '--expose-gc',
  '--import',
  '@beacon-observability/security-nodejs/register',
  '--import',
  resolve(root, 'tests/fixtures/otel-bootstrap.mjs'),
  entry,
];
const child = spawn(process.execPath, args, {
  cwd: root,
  env,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let stdout = '';
let stderr = '';
child.stdout.on('data', chunk => {
  stdout += chunk;
});
child.stderr.on('data', chunk => {
  stderr += chunk;
});
const result = {
  schemaVersion: 1,
  node: process.version,
  requestCount,
  concurrency,
  command: [process.execPath, ...args],
  status: 'fail',
};
try {
  const { ready } = await waitForReady(child);
  result.ready = ready;
  // Let the framework and HTTP instrumentation finish their first request
  // path before taking the baseline metrics sample.
  await request(ready.port, '/semantic?requestId=reclaim-warmup');
  const before = await request(ready.port, '/metrics');
  let next = 0;
  const workers = Array.from({ length: Math.max(1, concurrency) }, async () => {
    while (true) {
      const index = next++;
      if (index >= requestCount) return;
      const response = await request(
        ready.port,
        `/semantic?requestId=reclaim-${index}`
      );
      if (response.status !== 200)
        throw new Error(`http_status:${response.status}`);
    }
  });
  await Promise.all(workers);
  const after = await request(ready.port, '/metrics');
  result.metrics = { before: before.value, after: after.value };
  result.http = { status: 'pass', allHttp200: true };
} catch (error) {
  result.error = { message: error.message, stack: error.stack };
}
result.stop = await stop(child);
result.stdout = stdout.slice(-20_000);
result.stderr = stderr.slice(-20_000);
result.otel = tagged(stdout, 'BEACON_SECURITY_QA_OTEL').at(-1) || null;
try {
  result.health = JSON.parse(
    await readFile(resolve(securityOutput, 'health.json'), 'utf8')
  );
  result.reclamation = {
    activeRequests: result.health.active_requests,
    securityQueueDepth: result.health.delivery?.security_queue_depth,
    sbomQueueDepth: result.health.delivery?.sbom_queue_depth,
    requestsStarted: result.health.counts?.requests_started || 0,
    requestsCompleted: result.health.counts?.requests_completed || 0,
    requestsIncomplete: result.health.counts?.requests_incomplete || 0,
    deliveryLoss:
      result.health.delivery_loss ?? result.health.delivery?.dropped ?? null,
  };
} catch (error) {
  result.healthReadError = error.message;
}
result.durationMillis = Date.now() - startedAt;
result.status =
  result.error ||
  !result.stop.bounded ||
  result.http?.allHttp200 !== true ||
  result.reclamation?.activeRequests !== 0 ||
  result.reclamation?.securityQueueDepth !== 0
    ? 'fail'
    : 'pass';
await mkdir(resultsDir, { recursive: true });
await writeFile(
  resolve(resultsDir, 'summary.json'),
  `${JSON.stringify(result, null, 2)}\n`,
  'utf8'
);
process.stdout.write(
  `${JSON.stringify({ status: result.status, node: result.node, durationMillis: result.durationMillis, reclamation: result.reclamation, stop: result.stop })}\n`
);
if (result.status !== 'pass') process.exitCode = 1;
