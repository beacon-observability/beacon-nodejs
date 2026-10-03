import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { Agent, request as httpRequest } from 'node:http';
import { resolve } from 'node:path';

const root = resolve(new URL('../..', import.meta.url).pathname);
const resultsDir = resolve(
  process.env.BEACON_SECURITY_QA_RESULTS_DIR ||
    '/tmp/beacon_security-nodejs-reclaim-soak-results'
);
const securityOutput = resolve(
  process.env.BEACON_SECURITY_OUTPUT ||
    '/tmp/beacon_security-nodejs-reclaim-soak-output'
);
const durationMillis = Math.max(
  120_000,
  Number(process.env.BEACON_SECURITY_QA_RECLAIM_DURATION_MILLIS || 120_000)
);
const ratePerSecond = Math.max(
  20,
  Math.min(50, Number(process.env.BEACON_SECURITY_QA_RECLAIM_RATE || 25))
);
const concurrency = Math.max(
  1,
  Number(process.env.BEACON_SECURITY_QA_RECLAIM_CONCURRENCY || 16)
);
const fixture = resolve(root, 'tests/fixtures/reclaim/app.mjs');
const bootstrap = resolve(
  root,
  'tests/fixtures/reclaim/otel-counting-bootstrap.mjs'
);
const agent = new Agent({
  keepAlive: true,
  maxSockets: concurrency,
  maxFreeSockets: concurrency,
});

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

function sleep(milliseconds) {
  return new Promise(resolveSleep => setTimeout(resolveSleep, milliseconds));
}

function request(port, path, timeoutMillis = 10_000) {
  return new Promise((resolveRequest, reject) => {
    const value = httpRequest(
      { host: '127.0.0.1', port, path, agent },
      response => {
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
            /* flow is plain text */
          }
          resolveRequest({ status: response.statusCode, body, value: parsed });
        });
      }
    );
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
      () => reject(new Error(`startup_timeout:${stderr.slice(-1000)}`)),
      timeoutMillis
    );
    child.stdout.on('data', chunk => {
      stdout += chunk;
      const ready = tagged(stdout, 'BEACON_SECURITY_QA_READY')[0];
      if (ready) {
        clearTimeout(timer);
        resolveReady({ ready, stdout, stderr });
      }
    });
    child.stderr.on('data', chunk => {
      stderr += chunk;
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      reject(
        new Error(`startup_exit:${code}:${signal}:${stderr.slice(-1000)}`)
      );
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
    setTimeout(() => resolveTimeout({ timeout: true }), 10_000)
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
  BEACON_SECURITY_NODE_INCLUDE: fixture,
  BEACON_SECURITY_OUTPUT: securityOutput,
  BEACON_SECURITY_EXPORT_SECURITY_EVENTS_PER_SECOND: '1000',
  BEACON_SECURITY_EXPORT_SECURITY_BYTES_PER_SECOND: '10485760',
  BEACON_SECURITY_EXPORT_QUEUE_SIZE: '4096',
  BEACON_SECURITY_REQUESTS_PER_SECOND: '1000',
  OTEL_LOGS_EXPORTER: 'none',
  OTEL_METRICS_EXPORTER: 'none',
  NODE_OPTIONS: '',
};
const args = [
  '--expose-gc',
  '--import',
  '@beacon-observability/security-nodejs/register',
  '--import',
  bootstrap,
  fixture,
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
  durationMillis,
  ratePerSecond,
  concurrency,
  command: [process.execPath, ...args],
  status: 'fail',
  traffic: { attempted: 0, completed: 0, failed: 0, non200: 0 },
  samples: [],
};

async function sample(port, label) {
  const response = await request(port, '/__qa/metrics');
  const value = response.value || { parseError: response.body };
  const sample = {
    label,
    elapsedMillis: Date.now() - startedAt,
    status: response.status,
    ...value,
  };
  result.samples.push(sample);
  return sample;
}

try {
  const { ready } = await waitForReady(child);
  result.ready = ready;
  const warmup = await request(
    ready.port,
    `/flow?path=${encodeURIComponent(ready.fixtureFile)}`
  );
  result.traffic.warmup = { status: warmup.status, body: warmup.body };
  if (warmup.status !== 200)
    throw new Error(`warmup_status:${warmup.status}:${warmup.body}`);
  await sample(ready.port, 'initial');

  const startedTraffic = Date.now();
  const deadline = startedTraffic + durationMillis;
  const intervalMillis = 1000 / ratePerSecond;
  let nextAt = startedTraffic;
  let nextIndex = 0;
  const pending = new Set();
  let midpointSampled = false;
  const launch = index => {
    result.traffic.attempted += 1;
    const promise = request(
      ready.port,
      `/flow?path=${encodeURIComponent(ready.fixtureFile)}&request=${index}`
    )
      .then(response => {
        result.traffic.completed += 1;
        if (response.status !== 200) result.traffic.non200 += 1;
      })
      .catch(error => {
        result.traffic.failed += 1;
        result.traffic.lastError = error.message;
      })
      .finally(() => pending.delete(promise));
    pending.add(promise);
  };
  while (Date.now() < deadline) {
    if (!midpointSampled && Date.now() - startedTraffic >= durationMillis / 2) {
      await sample(ready.port, 'middle');
      midpointSampled = true;
    }
    if (pending.size >= concurrency) await Promise.race(pending);
    const now = Date.now();
    if (now < nextAt) await sleep(Math.min(nextAt - now, 100));
    if (Date.now() >= deadline) break;
    launch(nextIndex++);
    nextAt += intervalMillis;
    if (nextAt < Date.now() - intervalMillis * 4) nextAt = Date.now();
  }
  if (!midpointSampled) await sample(ready.port, 'middle');
  await Promise.all(pending);
  await sleep(500);
  await sample(ready.port, 'final');
  result.traffic.elapsedMillis = Date.now() - startedTraffic;
  result.http = {
    status: 'pass',
    all200: result.traffic.non200 === 0 && result.traffic.failed === 0,
    attempted: result.traffic.attempted,
    completed: result.traffic.completed,
  };
} catch (error) {
  result.error = { message: error.message, stack: error.stack };
}

result.stop = await stop(child);
agent.destroy();
result.stdout = stdout.slice(-30_000);
result.stderr = stderr.slice(-30_000);
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
    securityDropped: result.health.delivery?.security_dropped ?? null,
    sbomDropped: result.health.delivery?.sbom_dropped ?? null,
  };
} catch (error) {
  result.healthReadError = error.message;
}
result.durationMillisTotal = Date.now() - startedAt;
const initial = result.samples.find(sample => sample.label === 'initial');
const middle = result.samples.find(sample => sample.label === 'middle');
const final = result.samples.find(sample => sample.label === 'final');
result.assertions = {
  durationAtLeast120s: Boolean(result.traffic?.elapsedMillis >= 120_000),
  sustainedRateAtLeast20: Boolean(result.traffic?.attempted >= 2_400),
  allHttp200: result.http?.all200 === true,
  finalTrackingBytesZero: final?.trackingBytes === 0,
  finalActiveRequestsZero: final?.active_requests === 0,
  finalSecurityQueueZero: final?.security_queue_depth === 0,
  finalSbomQueueZero: final?.sbom_queue_depth === 0,
  samplesPresent: Boolean(initial && middle && final),
};
result.status =
  result.error ||
  !result.stop.bounded ||
  Object.values(result.assertions).some(value => value !== true)
    ? 'fail'
    : 'pass';
await mkdir(resultsDir, { recursive: true });
await writeFile(
  resolve(resultsDir, 'summary.json'),
  `${JSON.stringify(result, null, 2)}\n`,
  'utf8'
);
process.stdout.write(
  `${JSON.stringify({ status: result.status, node: result.node, durationMillisTotal: result.durationMillisTotal, traffic: result.traffic, assertions: result.assertions, reclamation: result.reclamation, stop: result.stop })}\n`
);
if (result.status !== 'pass') process.exitCode = 1;
