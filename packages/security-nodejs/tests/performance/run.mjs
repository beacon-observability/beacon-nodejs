import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { get as httpGet } from 'node:http';
import { resolve } from 'node:path';

const root = resolve(new URL('../..', import.meta.url).pathname);
const resultsDir = resolve(
  process.env.BEACON_SECURITY_QA_RESULTS_DIR ||
    '/tmp/beacon_security-nodejs-perf-results'
);
const framework = process.env.BEACON_SECURITY_QA_FRAMEWORK || 'express5';
const moduleSystem = process.env.BEACON_SECURITY_QA_MODULE_SYSTEM || 'esm';
const requestCount = Number(
  process.env.BEACON_SECURITY_QA_PERF_REQUESTS || 200
);
const concurrency = Number(
  process.env.BEACON_SECURITY_QA_PERF_CONCURRENCY || 8
);
const entry = resolve(
  root,
  `tests/fixtures/matrix/app.${moduleSystem === 'esm' ? 'mjs' : 'cjs'}`
);
const businessRoots = [
  resolve(root, 'tests/fixtures/matrix'),
  resolve(root, 'tests/fixtures/semantic'),
].join(',');

const modes = [
  {
    name: 'only-otel',
    security: false,
    env: {
      BEACON_SECURITY_ENABLED: 'false',
      BEACON_SECURITY_SBOM_ENABLED: 'false',
    },
    bootstrap: resolve(root, 'tests/fixtures/otel-only-bootstrap.mjs'),
  },
  {
    name: 'security',
    security: true,
    env: {
      BEACON_SECURITY_ENABLED: 'true',
      BEACON_SECURITY_SBOM_ENABLED: 'false',
      BEACON_SECURITY_NODE_INCLUDE: businessRoots,
    },
    bootstrap: resolve(root, 'tests/fixtures/otel-bootstrap.mjs'),
  },
  {
    name: 'sbom',
    security: true,
    env: {
      BEACON_SECURITY_ENABLED: 'true',
      BEACON_SECURITY_SBOM_ENABLED: 'true',
    },
    bootstrap: resolve(root, 'tests/fixtures/otel-bootstrap.mjs'),
  },
  {
    name: 'full',
    security: true,
    env: {
      BEACON_SECURITY_ENABLED: 'true',
      BEACON_SECURITY_SBOM_ENABLED: 'true',
      BEACON_SECURITY_NODE_INCLUDE: businessRoots,
    },
    bootstrap: resolve(root, 'tests/fixtures/otel-bootstrap.mjs'),
  },
];

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
    const requestValue = httpGet(
      {
        host: '127.0.0.1',
        port,
        path,
        headers: { accept: 'application/json' },
      },
      response => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', chunk => {
          body += chunk;
        });
        response.on('end', () => {
          let value;
          try {
            value = JSON.parse(body);
          } catch {
            value = null;
          }
          resolveRequest({ status: response.statusCode, value });
        });
      }
    );
    const timer = setTimeout(
      () => requestValue.destroy(new Error(`timeout:${path}`)),
      timeoutMillis
    );
    requestValue.on('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    requestValue.on('close', () => clearTimeout(timer));
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
        resolveReady({ ready, stdout, stderr });
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

function dropSummary(health) {
  const delivery = health?.delivery;
  if (!delivery || typeof delivery !== 'object') {
    return {
      status: 'unavailable',
      value: null,
      security: null,
      sbom: null,
      reason: 'package_drop_metric_not_exposed',
    };
  }
  const total = delivery.dropped ?? health.delivery_loss ?? null;
  return {
    status: total === null ? 'unavailable' : 'observed',
    value: total,
    security: delivery.security_dropped ?? null,
    sbom: delivery.sbom_dropped ?? null,
    source: 'health.json',
  };
}

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, 'exit').catch(() => {});
  child.kill('SIGTERM');
  const timer = new Promise(resolveTimer =>
    setTimeout(resolveTimer, 3_000, 'timeout')
  );
  if ((await Promise.race([exited.then(() => 'exit'), timer])) === 'timeout')
    child.kill('SIGKILL');
  await exited;
}

async function oneMode(mode) {
  const startedAt = process.hrtime.bigint();
  const env = {
    ...process.env,
    ...mode.env,
    ...(mode.security ? { BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'true' } : {}),
    BEACON_SECURITY_QA_FRAMEWORK: framework,
    BEACON_SECURITY_QA_MODULE_SYSTEM: moduleSystem,
    BEACON_SECURITY_OUTPUT: `/tmp/beacon_security-nodejs-perf/${mode.name}`,
    NODE_OPTIONS: '',
  };
  const args = [];
  if (mode.security)
    args.push(
      '--import',
      process.env.BEACON_SECURITY_QA_BEACON_SECURITY_PRELOAD ||
        '@beacon-observability/security-nodejs/register'
    );
  args.push('--import', mode.bootstrap, entry);
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
    mode: mode.name,
    framework,
    moduleSystem,
    command: [process.execPath, ...args],
    status: 'fail',
  };
  try {
    const { ready } = await waitForReady(child);
    result.startupMillis = Number(process.hrtime.bigint() - startedAt) / 1e6;
    result.ready = ready;
    for (let index = 0; index < 5; index += 1)
      await request(ready.port, `/semantic?requestId=warmup-${index}`);
    const latencies = [];
    let next = 0;
    const workers = Array.from(
      { length: Math.max(1, concurrency) },
      async () => {
        while (true) {
          const index = next;
          next += 1;
          if (index >= requestCount) return;
          const startedRequest = process.hrtime.bigint();
          const response = await request(
            ready.port,
            `/semantic?requestId=perf-${index}`
          );
          latencies.push({
            millis: Number(process.hrtime.bigint() - startedRequest) / 1e6,
            status: response.status,
          });
        }
      }
    );
    const throughputStarted = process.hrtime.bigint();
    await Promise.all(workers);
    const throughputMillis =
      Number(process.hrtime.bigint() - throughputStarted) / 1e6;
    const metrics = await request(ready.port, '/metrics');
    const sorted = latencies
      .map(entry => entry.millis)
      .sort((left, right) => left - right);
    const p95 = sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)];
    result.throughput = {
      requests: requestCount,
      concurrency,
      elapsedMillis: throughputMillis,
      requestsPerSecond: requestCount / (throughputMillis / 1000),
      p95Millis: p95,
      allHttp200: latencies.every(entry => entry.status === 200),
    };
    result.runtimeMetrics = metrics.value;
    // Read the bounded delivery counters from the diagnostic health snapshot;
    // keep total, security, and SBOM channels distinct in reports.
    result.drops = {
      status: 'unavailable',
      value: null,
      reason: 'package_drop_metric_not_exposed',
    };
  } catch (error) {
    result.error = { message: error.message, stack: error.stack };
    result.status =
      /ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND|Cannot find package|Cannot find module/.test(
        `${error.stack}\n${stderr}`
      )
        ? 'blocked'
        : 'fail';
  } finally {
    await stop(child);
    result.stdout = stdout.slice(-20_000);
    result.stderr = stderr.slice(-20_000);
    result.otel = tagged(stdout, 'BEACON_SECURITY_QA_OTEL').at(-1) || null;
    result.cleanup = {
      exitCode: child.exitCode,
      signal: child.signalCode,
      shutdownObserved: Boolean(result.otel),
    };
    if (mode.security) {
      try {
        const health = JSON.parse(
          await readFile(
            resolve(env.BEACON_SECURITY_OUTPUT, 'health.json'),
            'utf8'
          )
        );
        result.securityHealth = health;
        result.drops = dropSummary(health);
      } catch (error) {
        result.drops = {
          status: 'unavailable',
          value: null,
          reason: `health_snapshot_unavailable:${error.message}`,
        };
      }
    }
    if (
      !result.error &&
      result.throughput?.allHttp200 &&
      result.runtimeMetrics?.rssBytes &&
      result.otel?.started === true
    )
      result.status = 'pass';
    result.durationMillis = Number(process.hrtime.bigint() - startedAt) / 1e6;
    await mkdir(resultsDir, { recursive: true });
    await writeFile(
      resolve(resultsDir, `${mode.name}.json`),
      `${JSON.stringify(result, null, 2)}\n`,
      'utf8'
    );
  }
  return result;
}

const results = [];
for (const mode of modes) results.push(await oneMode(mode));
const summary = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  node: process.version,
  framework,
  moduleSystem,
  requestCount,
  concurrency,
  counts: results.reduce((counts, result) => {
    counts[result.status] = (counts[result.status] || 0) + 1;
    return counts;
  }, {}),
  results: results.map(({ mode, status, drops }) => ({ mode, status, drops })),
};
await mkdir(resultsDir, { recursive: true });
await writeFile(
  resolve(resultsDir, 'summary.json'),
  `${JSON.stringify(summary, null, 2)}\n`,
  'utf8'
);
process.stdout.write(`${JSON.stringify(summary)}\n`);
if ((summary.counts.fail || 0) > 0) process.exitCode = 1;
else if ((summary.counts.blocked || 0) > 0) process.exitCode = 2;
