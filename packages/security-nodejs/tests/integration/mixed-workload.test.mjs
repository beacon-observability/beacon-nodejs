import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const fixture = new URL('../fixtures/mixed-workload/', import.meta.url);
const register = fileURLToPath(
  new URL('../../src/register.mjs', import.meta.url)
);

async function exercise(withServices, enabled) {
  const root = await mkdtemp(join(tmpdir(), 'security-mixed-workload-'));
  const app = join(root, 'app.mjs');
  await copyFile(new URL('app.mjs', fixture), app);
  const child = fork(fileURLToPath(new URL('cluster.mjs', fixture)), [], {
    execArgv: ['--import', register],
    env: {
      ...process.env,
      NODE_OPTIONS: '',
      BEACON_SECURITY_ENABLED: String(enabled),
      BEACON_SECURITY_NODE_INCLUDE: root,
      BEACON_SECURITY_SBOM_ENABLED: 'false',
      BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'false',
      BEACON_SECURITY_CALL_DIAGNOSTICS_ENABLED: 'false',
      BEACON_SECURITY_QA_PG_URL: withServices
        ? process.env.BEACON_SECURITY_QA_PG_URL
        : '',
      BEACON_SECURITY_QA_REDIS_URL: withServices
        ? process.env.BEACON_SECURITY_QA_REDIS_URL
        : '',
      MIXED_APP_URL: pathToFileURL(app).href,
      OTEL_SDK_DISABLED: 'false',
      OTEL_TRACES_EXPORTER: 'none',
      OTEL_TRACES_SAMPLER: 'always_off',
      OTEL_METRICS_EXPORTER: 'none',
      OTEL_LOGS_EXPORTER: 'none',
    },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  let output = '';
  for (const stream of [child.stdout, child.stderr])
    stream.on('data', data => {
      output += data;
    });
  const ready = [],
    results = [];
  child.on('message', message => {
    if (message.type === 'ready') ready.push(message);
    if (message.type === 'result') results.push(message);
  });
  const exit = once(child, 'exit');
  async function until(check) {
    const deadline = Date.now() + 30000;
    while (!check()) {
      assert.equal(child.exitCode, null, output);
      assert.ok(Date.now() < deadline, output || 'cluster fixture timed out');
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  }
  try {
    await until(() => ready.length === 4);
    const routes = withServices
      ? [
          ...Array(40).fill('http'),
          ...Array(25).fill('db'),
          ...Array(15).fill('cache'),
          ...Array(15).fill('downstream'),
          ...Array(5).fill('waterfall'),
        ]
      : [...Array(16).fill('http'), ...Array(4).fill('downstream')];
    await Promise.all(
      ready.map(async worker => {
        // Batches exercise concurrent requests without exceeding tracking budgets.
        for (let start = 0; start < routes.length; start += 5) {
          await Promise.all(
            routes.slice(start, start + 5).map(async route => {
              const response = await fetch(
                `http://127.0.0.1:${worker.port}/${route}?id=7`
              );
              assert.equal(response.status, 200);
              assert.equal(await response.text(), 'ok');
            })
          );
        }
        const unknown = await fetch(
          `http://127.0.0.1:${worker.port}/unknown?id=7`
        );
        assert.equal(await unknown.text(), 'ok');
        const invalid = await fetch(
          `http://127.0.0.1:${worker.port}/http?id=bad`
        );
        assert.equal(invalid.status, 400);
        assert.equal(await invalid.text(), 'invalid id');
      })
    );
    child.send({ type: 'stop' });
    await until(() => results.length === 4);
    const [code] = await exit;
    assert.equal(code, 0, output);
    for (const result of results) {
      if (!enabled) {
        assert.equal(result.health, undefined);
        continue;
      }
      const health = result.health;
      assert.equal(
        health.counts.requests_started,
        routes.length + 2,
        JSON.stringify(result) + output
      );
      assert.equal(health.counts.requests_completed, routes.length + 2);
      assert.equal(health.active_requests, 0);
      assert.equal(health.delivery_loss, 0);
      assert.equal(
        health.counts.requests_incomplete,
        withServices ? 21 : 1,
        JSON.stringify(result)
      );
      assert.deepEqual(
        result.gaps,
        withServices
          ? {
              '/cache': { unmodeled_call_result: 15 },
              '/waterfall': { unmodeled_call_result: 5 },
              '/unknown': { unmodeled_call_result: 1 },
            }
          : { '/unknown': { unmodeled_call_result: 1 } }
      );
      for (const key of [
        'dropped',
        'security_dropped',
        'sbom_dropped',
        'security_queue_depth',
        'sbom_queue_depth',
      ])
        assert.equal(health.delivery[key], 0, key);
      for (const [key, count] of Object.entries(health.delivery.counters))
        if (/failed|shutdown_pending/.test(key)) assert.equal(count, 0, key);
    }
    return results;
  } finally {
    if (child.exitCode === null) {
      child.kill();
      await exit;
    }
    await rm(root, { recursive: true, force: true });
  }
}

test(
  'four cluster workers preserve HTTP/Promise behavior and incomplete accounting',
  { timeout: 60000 },
  async () => {
    await exercise(false, false);
    await exercise(false, true);
  }
);

test(
  'mixed PostgreSQL/Redis/HTTP requests retain explicit unsupported Redis coverage',
  {
    timeout: 60000,
    skip:
      !process.env.BEACON_SECURITY_QA_PG_URL ||
      !process.env.BEACON_SECURITY_QA_REDIS_URL
        ? 'set BEACON_SECURITY_QA_PG_URL and BEACON_SECURITY_QA_REDIS_URL for real services'
        : false,
  },
  async () => {
    await exercise(true, false);
    await exercise(true, true);
  }
);
