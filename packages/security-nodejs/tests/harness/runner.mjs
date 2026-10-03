import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const nodejsRoot = resolve(here, '../..');
const defaultEntry = resolve(nodejsRoot, 'tests/fixtures/matrix/app.mjs');
const defaultOtelBootstrap = resolve(
  nodejsRoot,
  'tests/fixtures/otel-bootstrap.mjs'
);

function parseTaggedLines(text, tag) {
  return text.split(/\r?\n/).flatMap(line => {
    if (!line.startsWith(`${tag} `)) return [];
    try {
      return [JSON.parse(line.slice(tag.length + 1))];
    } catch {
      return [];
    }
  });
}

function requestJson(
  port,
  path,
  timeoutMillis,
  { method = 'GET', body, headers = {} } = {}
) {
  return new Promise((resolveRequest, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const request = httpRequest(
      {
        host: '127.0.0.1',
        port,
        path,
        method,
        headers: {
          accept: 'application/json',
          ...(payload
            ? {
                'content-type': 'application/json',
                'content-length': Buffer.byteLength(payload),
              }
            : {}),
          ...headers,
        },
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
          } catch (error) {
            reject(
              new Error(`invalid_json:${error.message}:${body.slice(0, 200)}`)
            );
            return;
          }
          resolveRequest({
            status: response.statusCode,
            headers: response.headers,
            value,
          });
        });
      }
    );
    const timer = setTimeout(
      () => request.destroy(new Error(`request_timeout:${path}`)),
      timeoutMillis
    );
    request.on('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    request.on('close', () => clearTimeout(timer));
    if (payload) request.write(payload);
    request.end();
  });
}

function waitForReady(child, timeoutMillis) {
  return new Promise((resolveReady, reject) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const inspect = () => {
      const lines = parseTaggedLines(stdout, 'BEACON_SECURITY_QA_READY');
      if (lines[0]) finish(resolveReady, { ready: lines[0], stdout, stderr });
    };
    child.stdout.on('data', chunk => {
      stdout += chunk;
      inspect();
    });
    child.stderr.on('data', chunk => {
      stderr += chunk;
    });
    child.once('error', error => finish(reject, error));
    child.once('exit', (code, signal) => {
      if (!settled)
        finish(
          reject,
          new Error(`startup_exit:${code}:${signal}:${stderr.slice(0, 600)}`)
        );
    });
    const timer = setTimeout(
      () =>
        finish(reject, new Error(`startup_timeout:${stderr.slice(0, 600)}`)),
      timeoutMillis
    );
  });
}

async function stopChild(child, timeoutMillis) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exit = once(child, 'exit').catch(() => {});
  child.kill('SIGTERM');
  const timer = new Promise(resolveTimer =>
    setTimeout(resolveTimer, timeoutMillis, 'timeout')
  );
  if ((await Promise.race([exit.then(() => 'exit'), timer])) === 'timeout')
    child.kill('SIGKILL');
  await exit;
}

function check(condition, detail) {
  return { ok: Boolean(condition), detail };
}

function isMissingDependency(errorText) {
  return /ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND|Cannot find package|Cannot find module/.test(
    errorText
  );
}

function safeSlug(value) {
  return value.replace(/[^a-zA-Z0-9_.-]+/g, '-');
}

export async function runCase({
  framework,
  moduleSystem,
  nodeExecutable = process.execPath,
  nodeLine = process.env.BEACON_SECURITY_QA_NODE_LINE || null,
  entry = resolve(
    nodejsRoot,
    `tests/fixtures/matrix/app.${moduleSystem === 'esm' ? 'mjs' : 'cjs'}`
  ),
  otelBootstrap = defaultOtelBootstrap,
  securityPreload = process.env.BEACON_SECURITY_QA_BEACON_SECURITY_PRELOAD ||
    '@beacon-observability/security-nodejs/register',
  resultsDir = process.env.BEACON_SECURITY_QA_RESULTS_DIR ||
    '/tmp/beacon_security-nodejs-qa-results',
  timeoutMillis = 20_000,
} = {}) {
  const startedAt = Date.now();
  const environment = {
    ...process.env,
    BEACON_SECURITY_ENABLED: 'true',
    BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'true',
    BEACON_SECURITY_QA_FRAMEWORK: framework,
    BEACON_SECURITY_QA_MODULE_SYSTEM: moduleSystem,
    BEACON_SECURITY_QA_NODE_LINE: nodeLine || '',
    // Keep orchestration and OTel bootstrap outside the transformation set;
    // only the application fixture and its semantic business module are in
    // the explicit include roots.
    BEACON_SECURITY_NODE_INCLUDE: [
      resolve(nodejsRoot, 'tests/fixtures/matrix'),
      resolve(nodejsRoot, 'tests/fixtures/semantic'),
    ].join(','),
    BEACON_SECURITY_OUTPUT: resolve(
      resultsDir,
      'security-output',
      `${framework}-${moduleSystem}`
    ),
    NODE_OPTIONS: '',
  };
  const args = ['--import', securityPreload, '--import', otelBootstrap, entry];
  const child = spawn(nodeExecutable, args, {
    cwd: nodejsRoot,
    env: environment,
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
    status: 'fail',
    framework,
    moduleSystem,
    node: { executable: nodeExecutable, expectedLine: nodeLine, actual: null },
    command: [nodeExecutable, ...args],
    checks: {},
    skipped: [],
    startedAt: new Date(startedAt).toISOString(),
  };

  try {
    result.node.actual = process.version;
    const readyResult = await waitForReady(child, timeoutMillis);
    const ready = readyResult.ready;
    result.ready = ready;
    const actualMajor = Number(process.version.slice(1).split('.')[0]);
    const expectedMajor = nodeLine
      ? Number(String(nodeLine).split('.')[0])
      : null;
    result.checks.nodeLine = check(
      !expectedMajor || actualMajor === expectedMajor,
      { actual: process.version, expected: nodeLine }
    );
    result.checks.framework = check(ready.framework === framework, {
      actual: ready.framework,
      expected: framework,
    });
    result.checks.moduleSystem = check(ready.moduleSystem === moduleSystem, {
      actual: ready.moduleSystem,
      expected: moduleSystem,
    });
    result.checks.frameworkPackage = check(
      Boolean(
        ready.packageName &&
          ready.packageVersion &&
          !String(ready.packageVersion).startsWith('unknown:')
      ),
      { packageName: ready.packageName, packageVersion: ready.packageVersion }
    );

    const health = await requestJson(ready.port, '/health', 3_000);
    result.checks.health = check(
      health.status === 200 && health.value?.status === 'ok',
      health
    );
    const first = await requestJson(
      ready.port,
      '/semantic?requestId=qa-a',
      5_000
    );
    const second = await requestJson(
      ready.port,
      '/semantic?requestId=qa-b',
      5_000
    );
    const concurrent = await Promise.all([
      requestJson(ready.port, '/semantic?requestId=qa-concurrent-a', 5_000),
      requestJson(ready.port, '/semantic?requestId=qa-concurrent-b', 5_000),
    ]);
    result.observedTraceId = first.value?.activeSpan?.traceId || null;
    result.checks.semanticOriginal = check(
      first.status === 200 && first.value?.semanticOriginalPreserved === true,
      first.value
    );
    result.checks.semanticActiveContext = check(
      Boolean(
        first.value?.activeSpan?.hasActiveSpan &&
          first.value.activeSpan.traceId &&
          first.value.activeSpan.contextHasSpan
      ),
      first.value?.activeSpan
    );
    result.checks.crossRequestTraceIsolation = check(
      Boolean(
        first.value?.activeSpan?.traceId &&
          second.value?.activeSpan?.traceId &&
          first.value.activeSpan.traceId !== second.value.activeSpan.traceId
      ),
      { first: first.value?.activeSpan, second: second.value?.activeSpan }
    );
    result.checks.concurrentRequestTraceIsolation = check(
      concurrent.every(
        response =>
          response.status === 200 &&
          response.value?.semanticOriginalPreserved === true &&
          response.value?.activeSpan?.traceId
      ) &&
        new Set(concurrent.map(response => response.value.activeSpan.traceId))
          .size === concurrent.length,
      concurrent.map(response => response.value?.activeSpan)
    );
    const fs = await requestJson(ready.port, '/fs', 5_000);
    const childResult = await requestJson(ready.port, '/child', 5_000);
    const outbound = await requestJson(ready.port, '/outbound', 5_000);
    const error = await requestJson(ready.port, '/error', 5_000);
    const flowFixturePath = join(
      '/tmp',
      `security-node-flow-${ready.targetPort}.txt`
    );
    const positiveFlow = await requestJson(
      ready.port,
      `/flow/positive?path=${encodeURIComponent(flowFixturePath)}&q=qa-flow-query`,
      10_000,
      {
        method: 'POST',
        headers: { 'x-flow-header': 'qa-flow-header' },
        body: { sql: 'qa-flow-sql' },
      }
    );
    const negativeFlow = await requestJson(
      ready.port,
      '/flow/negative',
      10_000,
      {
        method: 'POST',
        headers: { 'x-flow-header': 'constant-header' },
        body: { sql: 'qa-negative-bound' },
      }
    );
    result.checks.fs = check(
      fs.status === 200 && fs.value?.value === 'qa-fs-value\n',
      fs.value
    );
    result.checks.childprocess = check(
      childResult.status === 200 &&
        childResult.value?.value === 'qa-child-value',
      childResult.value
    );
    result.checks.outbound = check(
      outbound.status === 200 &&
        outbound.value?.body === 'qa-target-value' &&
        outbound.value?.targetUrl?.includes('?qa=1') &&
        outbound.value?.targetRequests?.length === 1 &&
        outbound.value.targetRequests[0]?.url === '/target?qa=1' &&
        outbound.value.targetRequests[0]?.host?.startsWith('127.0.0.1:'),
      outbound.value
    );
    result.checks.exceptionOriginal = check(
      error.status === 500 &&
        (error.value?.error === 'qa-original-error' ||
          error.value?.message === 'qa-original-error'),
      error.value
    );
    result.checks.flowPositive = check(
      positiveFlow.status === 200 &&
        positiveFlow.value?.mode === 'positive' &&
        positiveFlow.value?.fileValue === 'qa-flow-file\n' &&
        positiveFlow.value?.childValue === 'qa-flow-child' &&
        positiveFlow.value?.targetBody === 'qa-target-value' &&
        positiveFlow.value?.targetRequests?.length === 1 &&
        positiveFlow.value.targetRequests[0]?.url ===
          '/target?flow=qa-flow-query' &&
        positiveFlow.value?.sql?.status === 'expected-error',
      positiveFlow.value
    );
    result.checks.flowNegative = check(
      negativeFlow.status === 200 &&
        negativeFlow.value?.mode === 'negative' &&
        negativeFlow.value?.fileValue === 'qa-flow-file\n' &&
        negativeFlow.value?.childValue === 'qa-flow-child' &&
        negativeFlow.value?.targetBody === 'qa-target-value' &&
        negativeFlow.value?.targetRequests?.length === 1 &&
        negativeFlow.value.targetRequests[0]?.url ===
          '/target?flow=constant-query' &&
        negativeFlow.value?.sql?.status === 'expected-error',
      negativeFlow.value
    );
    result.flowTraceIds = {
      positive: positiveFlow.value?.activeSpan?.traceId || null,
      negative: negativeFlow.value?.activeSpan?.traceId || null,
    };
    for (const driver of ['pg', 'mysql']) {
      const db = await requestJson(ready.port, `/sql?driver=${driver}`, 10_000);
      if (db.value?.status === 'skipped')
        result.skipped.push({ check: `${driver}Sql`, reason: db.value.reason });
      result.checks[`${driver}Sql`] = check(
        db.value?.status === 'skipped' ||
          (db.status === 200 &&
            db.value?.status === 'ok' &&
            db.value.positive === 'qa-bind' &&
            db.value.negative === "qa'bind"),
        db.value
      );
    }
  } catch (error) {
    result.error = { message: error.message, stack: error.stack };
    if (isMissingDependency(`${error.stack || ''}\n${stderr}\n${stdout}`)) {
      result.status = 'blocked';
      result.blockedReason = 'dependency_or_package_not_available';
    }
  } finally {
    await stopChild(child, 8_000);
    result.stdout = stdout.slice(-20_000);
    result.stderr = stderr.slice(-20_000);
    result.process = { exitCode: child.exitCode, signal: child.signalCode };
    result.otel =
      parseTaggedLines(stdout, 'BEACON_SECURITY_QA_OTEL').at(-1) || null;
    result.startupResult =
      parseTaggedLines(stdout, 'BEACON_SECURITY_QA_RESULT').at(-1) || null;
    try {
      result.securityHealth = JSON.parse(
        await readFile(
          resolve(environment.BEACON_SECURITY_OUTPUT, 'health.json'),
          'utf8'
        )
      );
      result.securityFindings = JSON.parse(
        await readFile(
          resolve(environment.BEACON_SECURITY_OUTPUT, 'findings.json'),
          'utf8'
        )
      );
      result.securityDelivery = result.securityHealth.delivery || null;
      result.checks.securitySnapshots = check(
        Boolean(result.securityHealth && result.securityFindings),
        { health: result.securityHealth, findings: result.securityFindings }
      );
    } catch (error) {
      if (securityPreload)
        result.checks.securitySnapshots = check(false, {
          error: error.message,
          path: environment.BEACON_SECURITY_OUTPUT,
        });
    }
    if (result.otel?.started) {
      const traceSpans =
        result.otel.spans?.filter(
          span => span.traceId === result.observedTraceId
        ) || [];
      const serverSpans = traceSpans.filter(
        span =>
          span.kind === 1 &&
          (span.attributes?.['http.request.method'] ||
            span.attributes?.['http.method'] ||
            /^GET\b/.test(span.name || ''))
      );
      result.otelServerSpanCount = serverSpans.length;
      result.checks.otelServerSpan = check(serverSpans.length >= 1, {
        traceId: result.observedTraceId,
        spans: traceSpans,
      });
    }
    const findings = result.securityFindings?.findings || [];
    const positiveTrace = result.flowTraceIds?.positive;
    const negativeTrace = result.flowTraceIds?.negative;
    const eventTraceId = event =>
      event.trace_id || event.last_trace_id || event.representative?.trace_id;
    const eventSources = event =>
      event.sources || event.representative?.sources || [];
    const eventSink = event => event.sink || event.representative?.sink;
    const positiveEvents = positiveTrace
      ? findings.filter(event => eventTraceId(event) === positiveTrace)
      : [];
    const negativeEvents = negativeTrace
      ? findings.filter(event => eventTraceId(event) === negativeTrace)
      : [];
    const expectedFlowRules = new Set([
      'path_traversal',
      'command_execution',
      'http_request_input',
      'sql_injection',
    ]);
    const observedFlowRules = new Set(positiveEvents.map(event => event.rule));
    const observedFlowRoles = new Set(
      positiveEvents.map(event => eventSink(event)?.role)
    );
    result.checks.flowEvidence = check(
      Boolean(positiveTrace) &&
        [...expectedFlowRules].every(rule => observedFlowRules.has(rule)) &&
        positiveEvents.every(
          event =>
            eventTraceId(event) === positiveTrace &&
            eventSources(event).length > 0 &&
            eventSink(event)?.role
        ),
      {
        positiveTrace,
        expectedRules: [...expectedFlowRules],
        observedRules: [...observedFlowRules],
        observedRoles: [...observedFlowRoles],
        events: positiveEvents,
      }
    );
    result.checks.flowNegativeNoFalsePositive = check(
      Boolean(negativeTrace) && negativeEvents.length === 0,
      { negativeTrace, events: negativeEvents }
    );
    if (result.status !== 'blocked') {
      const checks = Object.values(result.checks);
      result.status =
        checks.length > 0 &&
        checks.every(value => value.ok) &&
        result.otel?.started === true &&
        result.otel?.securityApiAvailable === true
          ? 'pass'
          : 'fail';
    }
    result.durationMillis = Date.now() - startedAt;
    await mkdir(resultsDir, { recursive: true });
    const file = resolve(
      resultsDir,
      `${safeSlug(`${framework}-${moduleSystem}`)}.json`
    );
    await writeFile(file, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
    result.resultFile = file;
  }
  return result;
}
