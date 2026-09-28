import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const externalEndpoint = process.env.BEACON_ZERO_CODE_EXTERNAL_ENDPOINT?.trim();
const receiverPort = Number(process.env.BEACON_ZERO_CODE_RECEIVER_PORT ?? '0');
if (
  !Number.isInteger(receiverPort) ||
  receiverPort < 0 ||
  receiverPort > 65535
) {
  throw new Error(
    'BEACON_ZERO_CODE_RECEIVER_PORT must be zero or a valid TCP port'
  );
}
const stagedPackage = await stagePackage(process.argv[2]);
const registerPath = stagedPackage.registerPath;
const appPath = path.join(root, 'examples/zero-code-demo/app.js');

const appSource = await readFile(appPath, 'utf8');
if (
  /(?:require\(|from\s+|import\s+)["'][^"']*(?:opentelemetry|beacon-observability|profiler-nodejs)/i.test(
    appSource
  )
) {
  throw new Error('zero-code demo must not import telemetry packages');
}

const received = [];
const receiver =
  externalEndpoint === undefined
    ? http.createServer((request, response) => {
        const chunks = [];
        request.on('data', chunk => chunks.push(chunk));
        request.on('end', () => {
          received.push({
            path: request.url,
            contentType: request.headers['content-type'] ?? '',
            body: Buffer.concat(chunks),
          });
          response.writeHead(200);
          response.end();
        });
      })
    : undefined;

if (receiver !== undefined) {
  await listen(receiver, receiverPort);
}

try {
  const receiverAddress = receiver?.address();
  const endpoint =
    externalEndpoint ??
    (receiverAddress !== null && typeof receiverAddress === 'object'
      ? `http://127.0.0.1:${receiverAddress.port}`
      : undefined);
  if (endpoint === undefined) {
    throw new Error('unable to determine zero-code receiver endpoint');
  }
  const usingExternalReceiver = externalEndpoint !== undefined;
  const protocol = usingExternalReceiver
    ? process.env.BEACON_ZERO_CODE_EXTERNAL_PROTOCOL?.trim() || 'grpc'
    : 'http/json';
  const child = spawn(process.execPath, [appPath], {
    env: {
      ...process.env,
      NODE_OPTIONS: `--require=${registerPath}`,
      APP_HOLD_MILLIS: '2800',
      OTEL_SERVICE_NAME: 'beacon-zero-code-smoke',
      OTEL_EXPORTER_OTLP_ENDPOINT: endpoint,
      OTEL_EXPORTER_OTLP_PROTOCOL: protocol,
      OTEL_TRACES_EXPORTER: 'otlp',
      OTEL_METRICS_EXPORTER: 'none',
      OTEL_LOGS_EXPORTER: 'none',
      OTEL_NODE_ENABLED_INSTRUMENTATIONS: 'http',
      OTEL_NODE_RESOURCE_DETECTORS: 'env,host,os,process,serviceinstance',
      OTEL_BSP_SCHEDULE_DELAY: '100',
      OTEL_LOG_LEVEL: usingExternalReceiver ? 'debug' : 'info',
      OTEL_PROFILING_ENABLED: usingExternalReceiver ? 'false' : 'true',
      OTEL_PROFILING_PPROF_UPLOAD_URL: `${endpoint}/profiles`,
      OTEL_PROFILING_EXPORT_INTERVAL: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const stdout = [];
  const stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));
  const exitCode = await waitForExit(child, 20_000, stdout, stderr);
  const output = Buffer.concat(stdout).toString();
  const errorOutput = Buffer.concat(stderr).toString();
  if (exitCode !== 0) {
    throw new Error(
      `instrumented application exited with ${exitCode}\n${output}\n${errorOutput}`
    );
  }
  if (!output.includes('plain application completed')) {
    throw new Error(`plain application did not complete\n${output}`);
  }

  if (usingExternalReceiver) {
    const diagnostics = `${output}\n${errorOutput}`;
    if (
      /(?:ECONNREFUSED|UNAVAILABLE|OTLPExporterError|ECONNRESET|ENOTFOUND)/i.test(
        diagnostics
      )
    ) {
      throw new Error(`external OTLP export failed\n${diagnostics}`);
    }
    console.log(
      `zero-code external smoke passed on ${endpoint} using ${protocol}`
    );
  } else {
    const traceRequests = received.filter(item => item.path === '/v1/traces');
    const traceSummary = summarizeTraces(traceRequests);
    if (
      !traceSummary.services.includes('beacon-zero-code-smoke') ||
      traceSummary.spanNames.length < 2
    ) {
      throw new Error(
        `zero-code trace payload did not contain the expected service and spans: ${JSON.stringify(
          traceSummary
        )}`
      );
    }

    const profileRequests = received.filter(item => item.path === '/profiles');
    if (
      !profileRequests.some(
        item =>
          item.contentType.includes('multipart/form-data') &&
          item.body.includes(Buffer.from('wall.pprof')) &&
          item.body.includes(Buffer.from('event.json')) &&
          item.body.includes(Buffer.from('beacon-zero-code-smoke'))
      )
    ) {
      throw new Error('no compatible multipart profile payload was received');
    }

    console.log(
      `zero-code smoke passed on ${endpoint}: ${traceRequests.length} trace request(s), ${profileRequests.length} profile request(s)`
    );
  }
} finally {
  if (receiver !== undefined) {
    await close(receiver);
  }
  await stagedPackage.cleanup();
}

async function stagePackage(explicitRegisterPath) {
  if (explicitRegisterPath !== undefined) {
    return {
      registerPath: path.resolve(explicitRegisterPath),
      async cleanup() {},
    };
  }

  execFileSync(
    'npm',
    ['run', 'compile', '--workspace=@beacon-observability/profiler-nodejs'],
    { cwd: root, stdio: 'pipe' }
  );
  execFileSync(
    'npm',
    ['run', 'compile', '--workspace=@beacon-observability/nodejs'],
    { cwd: root, stdio: 'pipe' }
  );

  const directory = await mkdtemp(
    path.join(os.tmpdir(), 'beacon-nodejs-zero-code-')
  );
  execFileSync(
    'npm',
    [
      'pack',
      '--workspace=@beacon-observability/profiler-nodejs',
      '--pack-destination',
      directory,
    ],
    { cwd: root, stdio: 'pipe' }
  );
  execFileSync(
    'npm',
    [
      'pack',
      '--workspace=@beacon-observability/nodejs',
      '--pack-destination',
      directory,
    ],
    { cwd: root, stdio: 'pipe' }
  );

  await writeFile(
    path.join(directory, 'package.json'),
    JSON.stringify({ private: true }, null, 2)
  );
  const profilerTarball = path.join(
    directory,
    'beacon-observability-profiler-nodejs-1.1.0.tgz'
  );
  const nodejsTarball = path.join(
    directory,
    'beacon-observability-nodejs-1.1.0.tgz'
  );
  execFileSync(
    'npm',
    ['install', '--no-package-lock', profilerTarball, nodejsTarball],
    {
      cwd: directory,
      env: {
        ...process.env,
        npm_config_fetch_retries: '1',
        npm_config_fetch_retry_maxtimeout: '20000',
        npm_config_prefer_offline: 'true',
      },
      stdio: 'pipe',
    }
  );
  execFileSync(
    process.execPath,
    [
      '-e',
      `const beacon = require('@beacon-observability/nodejs');
       const expected = ['HttpProfilingExporter', 'NodeProfiling', 'getNodeAutoInstrumentations', 'getResourceDetectors', 'startProfilingFromEnv'];
       const actual = Object.keys(beacon).sort();
       if (JSON.stringify(actual) !== JSON.stringify(expected)) {
         throw new Error('unexpected public exports: ' + actual.join(', '));
       }`,
    ],
    { cwd: directory, stdio: 'pipe' }
  );

  return {
    registerPath: path.join(
      directory,
      'node_modules/@beacon-observability/nodejs/build/src/register.js'
    ),
    async cleanup() {
      await rm(directory, { recursive: true, force: true });
    },
  };
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
}

function summarizeTraces(requests) {
  const services = new Set();
  const spanNames = [];
  for (const request of requests) {
    if (!request.contentType.includes('application/json')) {
      continue;
    }
    const payload = JSON.parse(request.body.toString());
    for (const resourceSpan of payload.resourceSpans ?? []) {
      for (const attribute of resourceSpan.resource?.attributes ?? []) {
        if (attribute.key === 'service.name') {
          services.add(attribute.value?.stringValue ?? '');
        }
      }
      for (const scopeSpan of resourceSpan.scopeSpans ?? []) {
        for (const span of scopeSpan.spans ?? []) {
          spanNames.push(span.name);
        }
      }
    }
  }
  return { services: Array.from(services), spanNames };
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close(error => (error ? reject(error) : resolve()));
  });
}

function waitForExit(child, timeoutMillis, stdout, stderr) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      reject(
        new Error(
          `instrumented application timed out after ${timeoutMillis}ms\n${Buffer.concat(
            stdout
          ).toString()}\n${Buffer.concat(stderr).toString()}`
        )
      );
    }, timeoutMillis);
    child.once('error', error => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once('exit', code => {
      clearTimeout(timeout);
      resolve(code);
    });
  });
}
