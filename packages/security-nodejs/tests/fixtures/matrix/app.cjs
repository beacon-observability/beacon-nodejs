const { readFile } = require('node:fs/promises');
const { createRequire } = require('node:module');
const { dirname, join } = require('node:path');
const {
  emitReady,
  emitResult,
  jsonResponse,
} = require('../common/protocol.cjs');
const { routeHandlers, targetServer, framework } = require('./app-core.cjs');

const requireFromHere = createRequire(__filename);
const moduleSystem = 'cjs';

function packageNameForFramework() {
  if (framework === 'express4')
    return process.env.BEACON_SECURITY_QA_EXPRESS4_PACKAGE || 'express4';
  if (framework === 'express5')
    return process.env.BEACON_SECURITY_QA_EXPRESS5_PACKAGE || 'express';
  if (framework === 'fastify5')
    return process.env.BEACON_SECURITY_QA_FASTIFY5_PACKAGE || 'fastify';
  throw new Error(`unsupported_framework:${framework}`);
}

async function loadFramework() {
  const packageName = packageNameForFramework();
  const loaded = requireFromHere(packageName);
  const factory = loaded.default || loaded;
  let version = null;
  try {
    let directory = dirname(requireFromHere.resolve(packageName));
    for (let depth = 0; depth < 8; depth += 1) {
      try {
        const metadata = JSON.parse(
          await readFile(join(directory, 'package.json'), 'utf8')
        );
        version = metadata.version;
        break;
      } catch {
        const parent = dirname(directory);
        if (parent === directory) break;
        directory = parent;
      }
    }
    if (!version) throw new Error('package_version_not_found');
  } catch (error) {
    version = `unknown:${error.code || error.message}`;
  }
  return { packageName, factory, version };
}

async function listen(server, port = 0) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function start() {
  const targetInfo = targetServer();
  const targetPort = await listen(targetInfo.target);
  const handlers = routeHandlers(targetPort, targetInfo.requests);
  const loaded = await loadFramework();
  let app;
  let server;
  if (framework.startsWith('express')) {
    app = loaded.factory();
    app.use(loaded.factory.json());
    app.get('/health', async (_req, res) => res.json(await handlers.health()));
    app.get('/semantic', async (req, res, next) => {
      try {
        res.json(
          await handlers.semantic(
            new URL(req.originalUrl, 'http://127.0.0.1').searchParams.get(
              'requestId'
            ) || 'request-a'
          )
        );
      } catch (error) {
        next(error);
      }
    });
    app.get('/fs', async (_req, res, next) => {
      try {
        res.json(await handlers.filesystem());
      } catch (error) {
        next(error);
      }
    });
    app.get('/child', async (_req, res, next) => {
      try {
        res.json(await handlers.childprocess());
      } catch (error) {
        next(error);
      }
    });
    app.get('/outbound', async (_req, res, next) => {
      try {
        res.json(await handlers.outbound());
      } catch (error) {
        next(error);
      }
    });
    app.post('/flow/:flowId', async (req, res, next) => {
      try {
        res.json(await handlers.flow(req.params.flowId, req, req.body || {}));
      } catch (error) {
        next(error);
      }
    });
    app.get('/sql', async (req, res, next) => {
      try {
        res.json(await handlers.sql(req.query.driver || 'pg'));
      } catch (error) {
        next(error);
      }
    });
    app.get('/metrics', async (_req, res, next) => {
      try {
        res.json(await handlers.metrics());
      } catch (error) {
        next(error);
      }
    });
    app.get('/error', () => {
      throw new Error('qa-original-error');
    });
    app.use((error, _req, res, _next) =>
      jsonResponse(res, 500, {
        error: error.message,
        name: error.name,
        stack: error.stack,
      })
    );
    server = await new Promise((resolve, reject) => {
      const value = app.listen(0, '127.0.0.1', () => resolve(value));
      value.once('error', reject);
    });
  } else {
    app = loaded.factory({ logger: false });
    app.get('/health', async () => handlers.health());
    app.get('/semantic', async request =>
      handlers.semantic(request.query?.requestId || 'request-a')
    );
    app.get('/fs', async () => handlers.filesystem());
    app.get('/child', async () => handlers.childprocess());
    app.get('/outbound', async () => handlers.outbound());
    app.post('/flow/:flowId', async request =>
      handlers.flow(request.params.flowId, request, request.body || {})
    );
    app.get('/sql', async request =>
      handlers.sql(request.query?.driver || 'pg')
    );
    app.get('/metrics', async () => handlers.metrics());
    app.get('/error', async () => {
      throw new Error('qa-original-error');
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    server = app.server;
  }
  const port = server.address().port;
  emitReady({
    port,
    targetPort,
    framework,
    moduleSystem,
    packageName: loaded.packageName,
    packageVersion: loaded.version,
  });

  async function stop(signal = 'SIGTERM') {
    try {
      if (globalThis.__securityQaShutdown)
        await globalThis.__securityQaShutdown({ signal, timeoutMillis: 2_000 });
    } finally {
      server.closeIdleConnections?.();
      server.closeAllConnections?.();
      await new Promise(resolve => server.close(() => resolve()));
      await new Promise(resolve => targetInfo.target.close(() => resolve()));
    }
  }

  process.once('SIGTERM', () =>
    stop().then(
      () => {
        // Allow a large final OTEL marker to drain before the harness exits.
        process.exitCode = 0;
      },
      error => {
        process.stderr.write(
          `BEACON_SECURITY_QA_SHUTDOWN_ERROR ${error.stack || error}\n`
        );
        process.exitCode = 1;
      }
    )
  );
  process.once('SIGINT', () =>
    stop('SIGINT').then(
      () => {
        process.exitCode = 0;
      },
      () => {
        process.exitCode = 1;
      }
    )
  );
}

start().catch(error => {
  emitResult({
    status: 'fail',
    phase: 'startup',
    error: error.stack || String(error),
  });
  process.exitCode = 1;
});
