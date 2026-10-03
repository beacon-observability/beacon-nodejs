import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { request as httpRequest } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const require = createRequire(import.meta.url);
const securityRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const BOUNDARY_FIXTURE = `
import { request as httpRequest } from 'node:http';

const fs = await import('node:fs/promises');
const readline = await import('node:readline');
const { createRequire } = await import('node:module');
const framework = process.env.BOUNDARY_FRAMEWORK;
const security = await import(process.env.BEACON_SECURITY_INDEX_URL);
const stateModule = await import(process.env.BEACON_SECURITY_STATE_URL);
const sdkNode = await import(process.env.OTEL_SDK_NODE_URL);
const otelApi = await import(process.env.OTEL_API_URL);
const traceBase = await import(process.env.OTEL_TRACE_BASE_URL);
const httpInstrumentation = await import(process.env.OTEL_HTTP_URL);
const expressInstrumentation = framework === 'express'
  ? await import(process.env.OTEL_EXPRESS_URL)
  : null;
const boundaryRequire = createRequire(process.env.BOUNDARY_PACKAGE_URL);
const frameworkModule = boundaryRequire(framework === 'express' ? 'express' : 'fastify');

const { shutdown } = security;
const { trackingBytes } = stateModule;
const { NodeSDK } = sdkNode;
const { trace } = otelApi;
const { InMemorySpanExporter, SimpleSpanProcessor } = traceBase;
const { HttpInstrumentation } = httpInstrumentation;
const { ExpressInstrumentation } = expressInstrumentation || {};
const filePath = process.env.BOUNDARY_FILE;
const defaultPath = process.env.BOUNDARY_FILE;
const coercePrefix = process.env.BOUNDARY_COERCE_PREFIX;
const traceExporter = new InMemorySpanExporter();
const sdk = new NodeSDK({
  spanProcessors: [new SimpleSpanProcessor(traceExporter)],
  instrumentations: [new HttpInstrumentation(), ...(framework === 'express' ? [new ExpressInstrumentation()] : [])],
});
await sdk.start();

const frameworkFactory = framework === 'express'
  ? (frameworkModule.default || frameworkModule)
  : (frameworkModule.default || frameworkModule.fastify || frameworkModule);
let server;
let app;
let pendingResolve;
let pendingValue;
let proxyReads = 0;

function writeTag(tag, value = {}) {
  process.stdout.write(tag + ' ' + JSON.stringify(value) + '\\n');
}

function readPath(value) {
  return fs.readFile(value, 'utf8')
    .then(content => ({ ok: true, content }))
    .catch(error => ({ ok: false, code: error.code || error.name || 'Error' }));
}

function sharedDag() {
  const shared = { value: 'dag-constant' };
  const root = { left: shared, right: shared };
  for (let index = 0; index < 1000; index += 1) root['shared' + index] = shared;
  return root;
}

function proxyBody() {
  const target = { value: 'proxy-constant' };
  const trap = () => { proxyReads += 1; };
  return new Proxy(target, {
    get(object, key, receiver) { trap(); return Reflect.get(object, key, receiver); },
    getPrototypeOf(object) { trap(); return Reflect.getPrototypeOf(object); },
    ownKeys(object) { trap(); return Reflect.ownKeys(object); },
    getOwnPropertyDescriptor(object, key) { trap(); return Reflect.getOwnPropertyDescriptor(object, key); },
  });
}

if (framework === 'express') {
  app = frameworkFactory();
  app.use(frameworkFactory.json());
  app.get('/get', async (request, response) => response.json(await readPath(request.get('x-input'))));
  app.get('/rewrite', async (request, response) => {
    request.headers['x-input'] = 'constant';
    return response.json(await readPath(request.get('x-input')));
  });
  app.get('/custom', async (request, response) => {
    request.get = () => 'constant';
    return response.json(await readPath(request.get('x-input')));
  });
  app.get('/pending', async (request, response) => {
    pendingValue = request.headers['x-input'];
    writeTag('BOUNDARY_PENDING', { captured: typeof pendingValue === 'string' });
    await new Promise(resolve => { pendingResolve = resolve; });
    return response.json({ ok: true, released: true });
  });
  server = await new Promise((resolve, reject) => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
    value.once('error', reject);
  });
} else {
  app = frameworkFactory({ logger: false });
  app.addHook('onRequest', async (request) => {
    if (request.url.startsWith('/query-rewrite')) request.query.path = 'constant';
  });
  app.addHook('preValidation', async (request) => {
    if (request.url.startsWith('/body-rewrite')) request.body.path = 'constant';
  });
  app.addContentTypeParser('text/plain', { parseAs: 'string' }, (_request, body, done) => done(null, body));
  app.addContentTypeParser('application/x-dag', { parseAs: 'string' }, (_request, _body, done) => done(null, sharedDag()));
  app.addContentTypeParser('application/x-proxy', { parseAs: 'string' }, (_request, _body, done) => done(null, proxyBody()));
  app.get('/query', async request => readPath(request.query.path));
  app.get('/query-rewrite', async request => readPath(request.query.path));
  app.get('/query-coerce', {
    schema: { querystring: { type: 'object', properties: { id: { type: 'integer' } } } },
  }, async request => readPath(coercePrefix + request.query.id));
  app.post('/body-rewrite', async request => readPath(request.body.path));
  app.post('/coerce', {
    schema: { body: { type: 'object', required: ['id'], properties: { id: { type: 'integer' } } } },
  }, async request => readPath(coercePrefix + request.body.id));
  app.post('/default', {
    schema: { body: { type: 'object', properties: { path: { type: 'string', default: defaultPath } } } },
  }, async request => readPath(request.body.path));
  app.post('/primitive', async request => readPath(request.body));
  app.post('/dag', async () => ({ ok: true }));
  app.post('/proxy', async () => ({ ok: true, proxyReads }));
  await app.listen({ port: 0, host: '127.0.0.1' });
  server = app.server;
}

writeTag('BOUNDARY_READY', { port: server.address().port, framework });

async function closeServer() {
  if (framework === 'express') {
    server.closeIdleConnections?.();
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(() => resolve()));
  } else {
    await app.close();
  }
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on('line', async line => {
  if (line === 'release') {
    pendingResolve?.();
    pendingResolve = undefined;
    return;
  }
  if (line === 'shutdown') {
    const first = shutdown({ timeoutMillis: 2_000 });
    const second = shutdown({ timeoutMillis: 2_000 });
    await first;
    writeTag('BOUNDARY_SHUTDOWN', { samePromise: first === second, trackingBytes: trackingBytes() });
    return;
  }
  if (line === 'exit') {
    await closeServer();
    const hostSpan = trace.getTracer('security-boundary-host').startSpan('host-after-security-shutdown');
    const sdkProvider = sdk._tracerProvider;
    hostSpan.end();
    await sdkProvider?.forceFlush?.();
    const spanCount = traceExporter.getFinishedSpans().length;
    await sdk.shutdown();
    writeTag('BOUNDARY_EXIT', { spanCount });
    process.exit(0);
  }
});
`;

function packageUrl(name) {
  return pathToFileURL(require.resolve(name)).href;
}

function waitTag(child, tag, timeoutMillis = 10_000) {
  const existing = child.boundaryLines.find(line => line.startsWith(`${tag} `));
  if (existing)
    return Promise.resolve(JSON.parse(existing.slice(tag.length + 1)));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.boundaryWaiters = child.boundaryWaiters.filter(
        waiter => waiter !== waiterRecord
      );
      reject(
        new Error(`boundary_timeout:${tag}:${child.boundaryStderr.slice(-500)}`)
      );
    }, timeoutMillis);
    const waiterRecord = {
      tag,
      resolve: value => {
        clearTimeout(timer);
        resolve(value);
      },
    };
    child.boundaryWaiters.push(waiterRecord);
  });
}

function attachOutput(child) {
  child.boundaryLines = [];
  child.boundaryWaiters = [];
  child.boundaryStderr = '';
  let partial = '';
  child.stdout.on('data', chunk => {
    partial += chunk.toString();
    const lines = partial.split(/\r?\n/);
    partial = lines.pop() || '';
    for (const line of lines) {
      child.boundaryLines.push(line);
      for (const waiter of [...child.boundaryWaiters]) {
        if (!line.startsWith(`${waiter.tag} `)) continue;
        child.boundaryWaiters = child.boundaryWaiters.filter(
          item => item !== waiter
        );
        waiter.resolve(JSON.parse(line.slice(waiter.tag.length + 1)));
      }
    }
  });
  child.stderr.on('data', chunk => {
    child.boundaryStderr += chunk.toString();
  });
}

function requestBody(port, path, { method = 'GET', body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload =
      body === undefined
        ? undefined
        : typeof body === 'string'
          ? body
          : JSON.stringify(body);
    const request = httpRequest(
      {
        host: '127.0.0.1',
        port,
        path,
        method,
        headers: {
          ...(payload === undefined
            ? {}
            : { 'content-length': Buffer.byteLength(payload) }),
          ...headers,
        },
      },
      response => {
        let value = '';
        response.setEncoding('utf8');
        response.on('data', chunk => {
          value += chunk;
        });
        response.on('end', () => {
          let parsed = value;
          try {
            parsed = JSON.parse(value);
          } catch {
            /* text response */
          }
          resolve({ status: response.statusCode, value: parsed });
        });
      }
    );
    request.once('error', reject);
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

async function runChild(framework, root, filePath) {
  const output = join(root, `${framework}-output`);
  const entry = join(root, `${framework}-boundary.mjs`);
  await writeFile(entry, BOUNDARY_FIXTURE, 'utf8');
  const environment = {
    ...process.env,
    BEACON_SECURITY_ENABLED: 'true',
    BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'true',
    BEACON_SECURITY_NODE_INCLUDE: root,
    BEACON_SECURITY_OUTPUT: output,
    BEACON_SECURITY_EVIDENCE_FILE: join(output, 'evidence.jsonl'),
    BEACON_SECURITY_SBOM_ENABLED: 'false',
    BEACON_SECURITY_RULES_PATH_TRAVERSAL_ENABLED: 'true',
    BEACON_SECURITY_RULES_HTTP_REQUEST_INPUT_ENABLED: 'true',
    OTEL_LOGS_EXPORTER: 'none',
    OTEL_METRICS_EXPORTER: 'none',
    BOUNDARY_FRAMEWORK: framework,
    BOUNDARY_PACKAGE_URL: pathToFileURL(join(securityRoot, 'package.json'))
      .href,
    BOUNDARY_FILE: filePath,
    BOUNDARY_COERCE_PREFIX: join(root, 'coerce-'),
    BEACON_SECURITY_INDEX_URL: pathToFileURL(
      join(securityRoot, 'src/index.mjs')
    ).href,
    BEACON_SECURITY_STATE_URL: pathToFileURL(
      join(securityRoot, 'src/core/state.mjs')
    ).href,
    OTEL_SDK_NODE_URL: packageUrl('@opentelemetry/sdk-node'),
    OTEL_API_URL: packageUrl('@opentelemetry/api'),
    OTEL_TRACE_BASE_URL: packageUrl('@opentelemetry/sdk-trace-base'),
    OTEL_HTTP_URL: packageUrl('@opentelemetry/instrumentation-http'),
    OTEL_EXPRESS_URL: packageUrl('@opentelemetry/instrumentation-express'),
    NODE_OPTIONS: '',
  };
  const child = spawn(
    process.execPath,
    ['--import', '@beacon-observability/security-nodejs/register', entry],
    {
      cwd: securityRoot,
      env: environment,
      stdio: ['pipe', 'pipe', 'pipe'],
    }
  );
  attachOutput(child);
  try {
    const ready = await waitTag(child, 'BOUNDARY_READY');
    if (framework === 'express') {
      const positive = await requestBody(ready.port, '/get', {
        headers: { 'x-input': filePath },
      });
      const rewritten = await requestBody(ready.port, '/rewrite', {
        headers: { 'x-input': filePath },
      });
      const custom = await requestBody(ready.port, '/custom', {
        headers: { 'x-input': filePath },
      });
      assert.equal(positive.status, 200);
      assert.equal(positive.value.ok, true);
      assert.equal(rewritten.status, 200);
      assert.equal(rewritten.value.ok, false);
      assert.equal(custom.status, 200);
      assert.equal(custom.value.ok, false);

      const pending = requestBody(ready.port, '/pending', {
        headers: { 'x-input': filePath },
      });
      await waitTag(child, 'BOUNDARY_PENDING');
      child.stdin.write('shutdown\n');
      const shutdownResult = await waitTag(child, 'BOUNDARY_SHUTDOWN');
      assert.equal(shutdownResult.samePromise, true);
      assert.equal(shutdownResult.trackingBytes, 0);
      child.stdin.write('release\n');
      const released = await pending;
      assert.equal(released.status, 200);
      assert.equal(released.value.released, true);
      child.stdin.write('exit\n');
      const exitResult = await waitTag(child, 'BOUNDARY_EXIT');
      assert.ok(
        exitResult.spanCount >= 1,
        `host OTel span must survive security shutdown: ${JSON.stringify(exitResult)}`
      );
    } else {
      const query = encodeURIComponent(filePath);
      const positiveQuery = await requestBody(
        ready.port,
        `/query?path=${query}`
      );
      const rewrittenQuery = await requestBody(
        ready.port,
        `/query-rewrite?path=${query}`
      );
      const queryCoerce = await requestBody(ready.port, '/query-coerce?id=7');
      const rewrittenBody = await requestBody(ready.port, '/body-rewrite', {
        method: 'POST',
        body: { path: filePath },
        headers: { 'content-type': 'application/json' },
      });
      const coerce = await requestBody(ready.port, '/coerce', {
        method: 'POST',
        body: { id: '7' },
        headers: { 'content-type': 'application/json' },
      });
      const defaulted = await requestBody(ready.port, '/default', {
        method: 'POST',
        body: {},
        headers: { 'content-type': 'application/json' },
      });
      const primitive = await requestBody(ready.port, '/primitive', {
        method: 'POST',
        body: filePath,
        headers: { 'content-type': 'text/plain' },
      });
      const dag = await requestBody(ready.port, '/dag', {
        method: 'POST',
        body: 'dag',
        headers: { 'content-type': 'application/x-dag' },
      });
      const proxy = await requestBody(ready.port, '/proxy', {
        method: 'POST',
        body: 'proxy',
        headers: { 'content-type': 'application/x-proxy' },
      });
      assert.equal(positiveQuery.value.ok, true);
      assert.equal(rewrittenQuery.value.ok, false);
      assert.equal(queryCoerce.value.ok, true);
      assert.equal(rewrittenBody.value.ok, false);
      assert.equal(coerce.value.ok, true);
      assert.equal(defaulted.value.ok, true);
      assert.equal(primitive.value.ok, true);
      assert.equal(dag.status, 200);
      assert.equal(proxy.status, 200);
      assert.ok(
        proxy.value.proxyReads <= 2,
        `proxy traversal must remain bounded: ${proxy.value.proxyReads}`
      );
      child.stdin.write('shutdown\n');
      await waitTag(child, 'BOUNDARY_SHUTDOWN');
      child.stdin.write('exit\n');
      await waitTag(child, 'BOUNDARY_EXIT');
    }
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit').catch(() => {});
      child.kill('SIGKILL');
      await exited;
    }
  }
  const health = JSON.parse(
    await readFile(join(output, 'health.json'), 'utf8')
  );
  const findingsEnvelope = JSON.parse(
    await readFile(join(output, 'findings.json'), 'utf8')
  );
  const findings = findingsEnvelope.findings || [];
  const evidencePath = join(output, 'evidence.jsonl');
  const evidence = (await readFile(evidencePath, 'utf8'))
    .split(/\r?\n/)
    .filter(Boolean)
    .map(line => JSON.parse(line));
  return { health, findings, evidence, lines: child.boundaryLines };
}

function eventSources(finding) {
  return finding.representative?.sources || finding.sources || [];
}

test(
  'real HTTP framework boundaries preserve and clear source marks',
  { concurrency: false },
  async () => {
    const root = await mkdtemp(
      join(tmpdir(), 'security-node-framework-boundaries-')
    );
    const filePath = join(root, 'boundary-input.txt');
    const coercePath = join(root, 'coerce-7');
    await writeFile(filePath, 'boundary-input\n', 'utf8');
    await writeFile(coercePath, 'coerce-input\n', 'utf8');
    try {
      const express = await runChild('express', root, filePath);
      const expressSources = express.findings.flatMap(eventSources);
      assert.ok(
        express.findings.some(finding => finding.rule === 'path_traversal')
      );
      assert.ok(
        expressSources.some(
          source =>
            source.location === 'express.request.headers' &&
            source.name.includes('x-input')
        )
      );
      assert.ok(
        express.evidence.some(
          event =>
            event.event_name === 'beacon.security.collection.incomplete' &&
            event.coverage_gaps?.includes('shutdown_during_request')
        )
      );
      assert.equal(express.health.status, 'incomplete');
      assert.ok((express.health.counts?.requests_incomplete || 0) >= 1);
      assert.ok(
        !express.evidence.some(
          event =>
            event.request?.route === '/rewrite' &&
            eventSources(event).some(source => source.name.includes('x-input'))
        )
      );
      assert.ok(
        !express.evidence.some(
          event =>
            event.request?.route === '/custom' &&
            eventSources(event).some(source => source.name.includes('x-input'))
        )
      );

      const fastify = await runChild('fastify', root, filePath);
      const fastifySources = fastify.findings.flatMap(eventSources);
      assert.ok(
        fastify.findings.some(finding => finding.rule === 'path_traversal')
      );
      assert.ok(
        fastifySources.some(
          source =>
            source.location === 'fastify.request.query' &&
            source.name.includes('query.path')
        )
      );
      assert.ok(
        fastifySources.some(
          source =>
            source.location === 'fastify.request.body' &&
            source.name.includes('body.id')
        )
      );
      assert.ok(
        fastifySources.some(
          source =>
            source.location === 'fastify.request.body' && source.name === 'body'
        )
      );
      const coerceFinding = fastify.findings.find(finding =>
        eventSources(finding).some(source => source.name.includes('body.id'))
      );
      assert.equal(
        coerceFinding?.representative?.confidence,
        'conservative_flow'
      );
      const queryCoerceFinding = fastify.findings.find(finding =>
        eventSources(finding).some(source => source.name.includes('query.id'))
      );
      assert.equal(
        queryCoerceFinding?.representative?.confidence,
        'conservative_flow'
      );
      assert.ok(
        !fastify.evidence.some(
          event =>
            event.request?.route === '/query-rewrite' &&
            eventSources(event).some(source =>
              source.name.includes('query.path')
            )
        )
      );
      assert.ok(
        !fastify.evidence.some(
          event =>
            event.request?.route === '/body-rewrite' &&
            eventSources(event).some(source =>
              source.name.includes('body.path')
            )
        )
      );
      assert.ok(
        !fastify.evidence.some(
          event =>
            event.request?.route === '/default' &&
            eventSources(event).some(source =>
              source.name.includes('body.path')
            )
        )
      );
      assert.ok(
        (fastify.health.counts?.sources || 0) < 64,
        'shared DAG must remain bounded'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
);
