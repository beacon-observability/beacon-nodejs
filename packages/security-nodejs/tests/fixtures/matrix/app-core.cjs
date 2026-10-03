const { execFile } = require('node:child_process');
const { mkdtemp, readFile, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { Server } = require('node:http');
const { promisify } = require('node:util');
const { monitorEventLoopDelay } = require('node:perf_hooks');
const { Client: PgClient } = require('pg');
const {
  assertSemanticResult,
  runSemanticScenario,
} = require('../semantic/operations.cjs');

const execFileAsync = promisify(execFile);
const framework = process.env.BEACON_SECURITY_QA_FRAMEWORK || 'express5';
const eventLoopHistogram = monitorEventLoopDelay({ resolution: 20 });
eventLoopHistogram.enable();

async function activeSpanInfo() {
  try {
    const api = require('@opentelemetry/api');
    const span = api.trace.getActiveSpan();
    const context = api.context.active();
    const spanContext = span && span.spanContext && span.spanContext();
    return {
      hasActiveSpan: Boolean(span),
      spanId: (spanContext && spanContext.spanId) || null,
      traceId: (spanContext && spanContext.traceId) || null,
      contextHasSpan: Boolean(api.trace.getSpan(context)),
    };
  } catch (error) {
    return {
      hasActiveSpan: false,
      traceId: null,
      spanId: null,
      contextHasSpan: false,
      error: error.code || error.message,
    };
  }
}

async function semanticPayload(requestId) {
  const value = await runSemanticScenario(requestId);
  return {
    value,
    semanticOriginalPreserved: assertSemanticResult(value, requestId),
    activeSpan: await activeSpanInfo(),
  };
}

async function filePayload() {
  const directory = await mkdtemp(`${tmpdir()}/security-node-qa-`);
  const path = `${directory}/fixture.txt`;
  try {
    await writeFile(path, 'qa-fs-value\n', 'utf8');
    return {
      path,
      value: await readFile(path, 'utf8'),
      activeSpan: await activeSpanInfo(),
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function childPayload() {
  const { stdout } = await execFileAsync(
    process.execPath,
    ['-e', "process.stdout.write('qa-child-value')"],
    { encoding: 'utf8', timeout: 2_000, windowsHide: true }
  );
  return { value: stdout, activeSpan: await activeSpanInfo() };
}

async function outboundPayload(targetPort, targetRequests = []) {
  const targetUrl = `http://127.0.0.1:${targetPort}/target?qa=1`;
  const response = await fetch(targetUrl, {
    headers: { 'x-security-qa': '1' },
  });
  return {
    targetUrl,
    status: response.status,
    body: await response.text(),
    targetRequests,
    activeSpan: await activeSpanInfo(),
  };
}

async function flowSql(value, positive) {
  if (typeof PgClient !== 'function')
    return { status: 'skipped', reason: 'pg_client_unavailable' };
  const client = new PgClient();
  const query = positive
    ? `select '${value}' as value`
    : 'select $1::text as value';
  const pending = positive ? client.query(query) : client.query(query, [value]);
  pending.catch(() => {});
  return { status: 'expected-error', error: 'unconnected_client_fixture' };
}

function flowChild(argument) {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      ['-e', "process.stdout.write('qa-flow-child')", argument],
      {
        encoding: 'utf8',
        timeout: 2_000,
        windowsHide: true,
      },
      (error, stdout) => (error ? reject(error) : resolve({ stdout }))
    );
  });
}

async function flowPayload(
  targetPort,
  targetRequests = [],
  mode = 'positive',
  request = {},
  body = {}
) {
  const positive = mode === 'positive';
  const query = request.query || {};
  const headers = request.headers || {};
  const flowId = (request.params && request.params.flowId) || mode;
  const fixturePath = `${tmpdir()}/security-node-flow-${targetPort}.txt`;
  await writeFile(fixturePath, 'qa-flow-file\n', 'utf8');
  const pathInput = positive
    ? String(query.path || body.path || fixturePath)
    : fixturePath;
  const outboundQuery = positive
    ? String(query.q || body.q || 'qa-flow-query')
    : 'constant-query';
  const headerInput = positive
    ? String(headers['x-flow-header'] || 'qa-flow-header')
    : 'constant-header';
  const sqlInput = positive
    ? String(body.sql || 'qa-flow-sql')
    : String(body.sql || 'qa-negative-bound');
  const childArgument = positive ? `${headerInput}:${flowId}` : 'constant-arg';
  const targetRequestStart = targetRequests.length;
  try {
    const fileValue = await Promise.resolve(pathInput).then(path =>
      readFile(path, 'utf8')
    );
    const child = await flowChild(childArgument);
    const targetUrl = `http://127.0.0.1:${targetPort}/target?flow=${outboundQuery}`;
    const response = await fetch(targetUrl, {
      headers: { 'x-security-flow': headerInput },
    });
    const sql = await flowSql(sqlInput, positive);
    return {
      status: 'ok',
      mode,
      flowId,
      fileValue,
      childValue: child.stdout,
      targetUrl,
      targetStatus: response.status,
      targetBody: await response.text(),
      targetRequests: targetRequests.slice(targetRequestStart),
      sql,
      activeSpan: await activeSpanInfo(),
    };
  } finally {
    await rm(fixturePath, { force: true });
  }
}

async function sqlPayload(driver) {
  const url =
    process.env[
      driver === 'pg'
        ? 'BEACON_SECURITY_QA_PG_URL'
        : 'BEACON_SECURITY_QA_MYSQL_URL'
    ];
  if (!url) return { status: 'skipped', reason: `missing_${driver}_url` };
  if (driver === 'pg') {
    const { Client } = require('pg');
    const client = new Client({ connectionString: url });
    await client.connect();
    try {
      const positive = await client.query('select $1::text as value', [
        'qa-bind',
      ]);
      const negative = await client.query('select $1::text as value', [
        "qa'bind",
      ]);
      return {
        status: 'ok',
        positive: positive.rows[0] && positive.rows[0].value,
        negative: negative.rows[0] && negative.rows[0].value,
      };
    } finally {
      await client.end();
    }
  }
  const mysql = require('mysql2/promise');
  const connection = await mysql.createConnection(url);
  try {
    const [positive] = await connection.execute('select ? as value', [
      'qa-bind',
    ]);
    const [negative] = await connection.execute('select ? as value', [
      "qa'bind",
    ]);
    return {
      status: 'ok',
      positive: positive[0] && positive[0].value,
      negative: negative[0] && negative[0].value,
    };
  } finally {
    await connection.end();
  }
}

function targetServer() {
  const requests = [];
  const target = new Server((req, res) => {
    requests.push({ method: req.method, url: req.url, host: req.headers.host });
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('qa-target-value');
  });
  return { target, requests };
}

function routeHandlers(targetPort, targetRequests = []) {
  return {
    async health() {
      return { status: 'ok', framework, moduleSystem: 'cjs' };
    },
    async semantic(requestId = 'request-a') {
      return { status: 'ok', requestId, ...(await semanticPayload(requestId)) };
    },
    async filesystem() {
      return { status: 'ok', ...(await filePayload()) };
    },
    async childprocess() {
      return { status: 'ok', ...(await childPayload()) };
    },
    async outbound() {
      return {
        status: 'ok',
        ...(await outboundPayload(targetPort, targetRequests)),
      };
    },
    async flow(mode, request, body) {
      return {
        status: 'ok',
        ...(await flowPayload(targetPort, targetRequests, mode, request, body)),
      };
    },
    async sql(driver) {
      return sqlPayload(driver);
    },
    async metrics() {
      return {
        rssBytes: process.memoryUsage().rss,
        eventLoopDelayP95Millis: eventLoopHistogram.percentile(95) / 1e6,
        eventLoopDelayMaxMillis: eventLoopHistogram.max / 1e6,
      };
    },
  };
}

function parseBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', chunk => {
      body += chunk;
    });
    request.on('end', () => resolve(body ? JSON.parse(body) : {}));
    request.on('error', reject);
  });
}

module.exports = {
  framework,
  activeSpanInfo,
  semanticPayload,
  filePayload,
  childPayload,
  outboundPayload,
  flowPayload,
  sqlPayload,
  targetServer,
  routeHandlers,
  parseBody,
};
