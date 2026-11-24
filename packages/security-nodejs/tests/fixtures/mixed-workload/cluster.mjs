import cluster from 'node:cluster';

if (cluster.isPrimary) {
  let remaining = 4;
  for (let i = 0; i < 4; i++) {
    const worker = cluster.fork();
    worker.on('message', message =>
      process.send({ ...message, worker: worker.id })
    );
    worker.on('exit', code => {
      if (code) process.exitCode = code;
      if (--remaining === 0) process.disconnect();
    });
  }
  process.on('message', message => {
    for (const worker of Object.values(cluster.workers)) worker.send(message);
  });
  process.on('disconnect', () => {
    for (const worker of Object.values(cluster.workers)) worker.kill();
  });
} else {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const security = await import('../../../src/index.mjs');
  const { getRuntime, current } = await import('../../../src/core/runtime.mjs');
  const { NodeSDK } = require('@opentelemetry/sdk-node');
  const {
    HttpInstrumentation,
  } = require('@opentelemetry/instrumentation-http');
  const {
    ExpressInstrumentation,
  } = require('@opentelemetry/instrumentation-express');
  const sdk = new NodeSDK({
    instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
  });
  await sdk.start();
  const express = require('express');
  const http = require('node:http');
  let pool, cache;
  if (
    process.env.BEACON_SECURITY_QA_PG_URL &&
    process.env.BEACON_SECURITY_QA_REDIS_URL
  ) {
    const { Pool } = require('pg');
    const { createClient } = require('redis');
    pool = new Pool({
      connectionString: process.env.BEACON_SECURITY_QA_PG_URL,
    });
    cache = createClient({ url: process.env.BEACON_SECURITY_QA_REDIS_URL });
    cache.on('error', () => {});
    await cache.connect();
    await cache.set('beacon-issue37:7', 'fixed-cache');
  }
  const downstream = http.createServer((_request, response) =>
    response.end('fixed-downstream')
  );
  await new Promise(resolve =>
    downstream.listen({ host: '127.0.0.1', port: 0, exclusive: true }, resolve)
  );
  const app = express();
  const gaps = {};
  const routes = new WeakMap();
  app.use((request, _response, next) => {
    const state = current();
    if (state) routes.set(state, request.url.split('?')[0]);
    next();
  });
  const runtime = getRuntime();
  if (runtime) {
    const end = runtime.exporter.ledger.end.bind(runtime.exporter.ledger);
    runtime.exporter.ledger.end = state => {
      const route = routes.get(state);
      for (const reason of state.gaps) {
        gaps[route] ??= {};
        gaps[route][reason] = (gaps[route][reason] || 0) + 1;
      }
      return end(state);
    };
  }
  const { configure } = await import(process.env.MIXED_APP_URL);
  const destroyAgent = configure(
    app,
    pool,
    cache,
    'http://127.0.0.1:' + downstream.address().port
  );
  const server = await new Promise(resolve => {
    const server = app.listen(
      { host: '127.0.0.1', port: 0, exclusive: true },
      () => resolve(server)
    );
  });
  process.send({ type: 'ready', port: server.address().port });
  process.on('message', async message => {
    if (message.type !== 'stop') return;
    await new Promise(resolve => server.close(resolve));
    destroyAgent();
    await new Promise(resolve => downstream.close(resolve));
    await pool?.end();
    await cache?.quit();
    await security.shutdown();
    const health = runtime?.exporter.ledger.health(runtime.exporter.delivery());
    await sdk.shutdown();
    process.send({ type: 'result', health, gaps }, () => process.disconnect());
  });
}
