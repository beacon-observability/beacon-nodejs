import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import http from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import test, { after } from 'node:test';
import expressModule from 'express';
import fastifyModule from 'fastify';

process.env.BEACON_SECURITY_ENABLED = 'true';
process.env.BEACON_SECURITY_NODE_INCLUDE = process.cwd();
process.env.BEACON_SECURITY_SBOM_ENABLED = 'false';
const rt = await import('../src/core/runtime.mjs');
const { installFramework } = await import('../src/adapters/frameworks.mjs');
const { installBuiltins, installLibrary } = await import(
  '../src/adapters/sinks.mjs'
);
const values = await import('../src/core/values.mjs');
const operations = await import('../src/core/operations.mjs');
const calls = await import('../src/core/calls.mjs');
const { transform } = await import('../src/transform/index.mjs');
globalThis[Symbol.for('beacon.security.helpers.v1')] = {
  ...values,
  ...operations,
  ...calls,
};
installBuiltins();
rt.start();
const keepAlive = setInterval(() => {}, 1000);
after(async () => {
  await rt.shutdown();
  clearInterval(keepAlive);
});
const express = installFramework('express', expressModule, '5.2.1');
const fastify = installFramework('fastify', fastifyModule, '5.7.4');

async function withServer(app, run) {
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    return await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test('transformed repeated query reads retain a later SQL flow with copy-on-write isolation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'beacon-express-query-'));
  const filename = join(directory, 'route.mjs');
  const source = `
    export function route(request, response, client, state) {
      for (let i = 0; i < 4200; i++) request.query.q;
      const first = request.query, second = request.query;
      first.q = 'constant';
      client.query(first.q);
      const clean = state.pending.length;
      client.query('SELECT ' + second.q.trim());
      client.query('SELECT ' + request.query.q.trim());
      response.json({ clean, findings: state.pending.length, bytes: state.bytes, truncated: state.truncated,
        actual: first.q, fresh: request.query.q, distinct: first !== second });
    }
  `;
  await writeFile(
    filename,
    transform(source, filename, pathToFileURL(filename).href).code
  );
  const fixture = await import(pathToFileURL(filename));
  class Client {
    query(text) {
      return text;
    }
  }
  installLibrary('pg', { Client });
  const app = express();
  app.get('/', (req, res) =>
    fixture.route(req, res, new Client(), rt.current())
  );
  try {
    await withServer(app, async url => {
      const result = await (await fetch(url + '/?q=%20Alice%20')).json();
      assert.equal(result.clean, 0);
      assert.equal(result.findings, 2);
      assert.equal(result.truncated, false);
      assert.ok(result.bytes < 300000);
      assert.equal(result.distinct, true);
      assert.equal(result.actual, 'constant');
      assert.equal(result.fresh, ' Alice ');
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('late Express router continuation does not reopen completed state', async () => {
  const app = express(),
    router = express.Router();
  let finish;
  const continued = new Promise(resolve => {
    finish = resolve;
  });
  app.use((req, res, next) => {
    res.end('ok');
    setImmediate(next);
  });
  router.use(() => {
    finish(rt.current());
  });
  app.use(router);
  await withServer(app, async url => {
    await (await fetch(url)).text();
    assert.equal(await continued, undefined);
    assert.equal(rt.getRuntime().exporter.ledger.activeRequests, 0);
  });
  const response = new EventEmitter();
  response.writableFinished = true;
  assert.equal(rt.begin({}, response), undefined);
});

test('Security leaves real ServerResponse error handling under application control', async () => {
  const app = express();
  const failure = new Error('synthetic response failure');
  app.use((req, res) => {
    assert.equal(res.listenerCount('error'), 0);
    assert.throws(
      () => res.emit('error', failure),
      error => error === failure
    );
    res.end('ok');
  });
  await withServer(app, async url =>
    assert.equal(await (await fetch(url)).text(), 'ok')
  );
});

test('Fastify continues callback and async abort hooks after an incomplete body disconnect', async () => {
  const app = fastify();
  let ready, aborted;
  const received = new Promise(resolve => {
    ready = resolve;
  });
  const completed = new Promise(resolve => {
    aborted = resolve;
  });
  const order = [];
  app.addHook('onRequest', (request, reply, done) => {
    ready();
    done();
  });
  app.addHook('onRequestAbort', (request, done) => {
    order.push('callback');
    done();
  });
  app.addHook('onRequestAbort', async _request => {
    order.push('async');
    aborted();
  });
  app.post('/', async () => ({ ok: true }));
  await app.listen({ host: '127.0.0.1', port: 0 });
  try {
    const request = http.request({
      host: '127.0.0.1',
      port: app.server.address().port,
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': 1000 },
    });
    request.on('error', () => {});
    request.write('{');
    await received;
    request.destroy();
    await completed;
    assert.deepEqual(order, ['callback', 'async']);
  } finally {
    await app.close();
  }
});
