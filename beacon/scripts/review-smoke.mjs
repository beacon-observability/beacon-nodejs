import assert from 'node:assert/strict';
import { execFile as execFileCallback, spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const root = fileURLToPath(new URL('../..', import.meta.url));
const directory = await mkdtemp(path.join(os.tmpdir(), 'beacon-review-smoke-'));
const children = new Set();
const received = [];
const receiver = http.createServer((request, response) => {
  const chunks = [];
  request.on('data', chunk => chunks.push(chunk));
  request.on('end', () => {
    received.push({ path: request.url, body: Buffer.concat(chunks) });
    response.writeHead(200);
    response.end('{}');
  });
});
await new Promise(resolve => receiver.listen(0, '127.0.0.1', resolve));
const endpoint = `http://127.0.0.1:${receiver.address().port}`;
const environment = {
  ...process.env,
  NODE_OPTIONS: '',
  BEACON_SECURITY_ENABLED: 'false',
  OTEL_SERVICE_NAME: '',
  OTEL_RESOURCE_ATTRIBUTES: 'service.name=checkout,service.version=v%201',
  OTEL_EXPORTER_OTLP_ENDPOINT: endpoint,
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: `${endpoint}/v1/traces`,
  OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: `${endpoint}/v1/logs`,
  OTEL_EXPORTER_OTLP_PROTOCOL: 'http/json',
  OTEL_EXPORTER_OTLP_TRACES_PROTOCOL: 'http/json',
  OTEL_EXPORTER_OTLP_LOGS_PROTOCOL: 'http/json',
  OTEL_EXPORTER_OTLP_HEADERS: '',
  OTEL_EXPORTER_OTLP_TRACES_HEADERS: '',
  OTEL_EXPORTER_OTLP_LOGS_HEADERS: '',
  OTEL_TRACES_EXPORTER: 'otlp',
  OTEL_METRICS_EXPORTER: 'none',
  OTEL_LOGS_EXPORTER: 'otlp',
  OTEL_NODE_ENABLED_INSTRUMENTATIONS: 'http',
  OTEL_NODE_DISABLED_INSTRUMENTATIONS: '',
  OTEL_NODE_RESOURCE_DETECTORS: 'env',
  OTEL_BSP_SCHEDULE_DELAY: '50',
  OTEL_BLRP_SCHEDULE_DELAY: '60000',
  OTEL_PROFILING_ENABLED: 'false',
  OTEL_SDK_DISABLED: 'false',
  OTEL_PROFILING_PPROF_HEADERS: '',
  OTEL_PROFILING_PPROF_UPLOAD_URL: `${endpoint}/profiles`,
  BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'false',
  BEACON_SECURITY_OUTPUT: path.join(directory, 'security-output'),
  BEACON_SECURITY_CONTROL_FILE: path.join(directory, 'test-control.json'),
  BEACON_SECURITY_EVIDENCE_FILE: '',
};
const register = path.join(
  directory,
  'node_modules/@beacon-observability/nodejs/register.mjs'
);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const passed = [];

async function command(binary, args, cwd = root) {
  try {
    return await execFile(binary, args, {
      cwd,
      timeout: 120000,
      maxBuffer: 8 * 1024 * 1024,
      env: {
        ...process.env,
        npm_config_prefer_offline: 'true',
        npm_config_fetch_retries: '1',
      },
    });
  } catch (error) {
    throw new Error(
      `${binary} ${args.join(' ')} failed: ${String(error.stderr || error.message).slice(-4000)}`
    );
  }
}
async function file(name, text) {
  const filename = path.join(directory, name);
  await writeFile(filename, text);
  return filename;
}
function launch(filename, extra = {}, imports = [register]) {
  const child = spawn(
    process.execPath,
    [...imports.flatMap(item => ['--import', item]), filename],
    {
      cwd: directory,
      env: { ...environment, ...extra },
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  );
  children.add(child);
  child.output = '';
  child.errors = '';
  child.stdout.on('data', data => {
    child.output = (child.output + data).slice(-65536);
  });
  child.stderr.on('data', data => {
    child.errors = (child.errors + data).slice(-65536);
  });
  child.once('exit', () => children.delete(child));
  return child;
}
async function until(predicate, child, timeout = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const value = predicate();
    if (value) return value;
    if (child && (child.exitCode !== null || child.signalCode !== null))
      throw new Error(
        `child exited early ${child.exitCode}/${child.signalCode}: ${child.output}\n${child.errors}`
      );
    await delay(10);
  }
  throw new Error(`review smoke timeout: ${child?.output}\n${child?.errors}`);
}
async function exited(child, timeout = 15000) {
  await until(
    () => child.exitCode !== null || child.signalCode !== null,
    null,
    timeout
  );
  return { code: child.exitCode, signal: child.signalCode };
}
function logs() {
  return received
    .filter(item => item.path === '/v1/logs')
    .flatMap(item => {
      const body = JSON.parse(item.body.toString());
      return (body.resourceLogs || []).flatMap(resource =>
        (resource.scopeLogs || []).flatMap(scope => scope.logRecords || [])
      );
    })
    .flatMap(record => {
      try {
        return [JSON.parse(record.body.stringValue)];
      } catch {
        return [];
      }
    });
}

try {
  for (const name of ['profiler-nodejs', 'nodejs'])
    await command('npm', [
      'run',
      'compile',
      `--workspace=@beacon-observability/${name}`,
    ]);
  const archives = [];
  for (const name of ['profiler-nodejs', 'security-nodejs', 'nodejs']) {
    const result = await command('npm', [
      'pack',
      '--json',
      `--workspace=@beacon-observability/${name}`,
      '--pack-destination',
      directory,
    ]);
    archives.push(path.join(directory, JSON.parse(result.stdout)[0].filename));
  }
  await file('package.json', JSON.stringify({ private: true }));
  await command(
    'npm',
    [
      'install',
      '--no-package-lock',
      '--no-audit',
      '--no-fund',
      ...archives,
      'express@5.2.1',
    ],
    directory
  );

  const optional = await file(
    'optional.cjs',
    `
    (async()=>{
    const assert = require('node:assert/strict'), Module = require('node:module');
    const original = Module._load;
    let packageFailure=false, bindingAttempts=0;
    Module._load = function(name, ...args) {
      if(name==='@datadog/pprof') { bindingAttempts++; throw new Error('synthetic missing binding'); }
      if(packageFailure && name === '@beacon-observability/profiler-nodejs') throw new Error('synthetic package failure');
      return Reflect.apply(original, this, [name, ...args]);
    };
    const {startProfilingFromEnv} = require('@beacon-observability/nodejs');
    assert.equal(startProfilingFromEnv({}), undefined);
    assert.equal(Object.keys(require.cache).some(name => name.endsWith('.node')), false);
    const profiler=startProfilingFromEnv({ OTEL_PROFILING_ENABLED:'true', OTEL_PROFILING_PPROF_UPLOAD_URL:'http://127.0.0.1' });
    await new Promise(resolve=>setImmediate(resolve));
    assert.equal(bindingAttempts,1);
    await profiler.shutdown();
    packageFailure=true;
    assert.equal(startProfilingFromEnv({ OTEL_PROFILING_ENABLED:'true', OTEL_PROFILING_PPROF_UPLOAD_URL:'http://127.0.0.1' }), undefined);
    })().catch(error=>{console.error(error);process.exitCode=1;});
  `
  );
  assert.deepEqual(await exited(launch(optional, {}, [])), {
    code: 0,
    signal: null,
  });
  passed.push(
    'disabled profiling avoids native loading; unavailable binding fails open'
  );

  const idle = await file(
    'idle.cjs',
    `
    const {NodeProfiling}=require('@beacon-observability/profiler-nodejs');
    new NodeProfiling({ exporter:{ export:async()=>{} }, profileTypes:['wall'],
      intervalMillis:60000, wallDurationMillis:60000 }).start();
  `
  );
  assert.deepEqual(await exited(launch(idle, {}, []), 5000), {
    code: 0,
    signal: null,
  });
  passed.push(
    'native background wall profiling does not retain an idle process'
  );

  await mkdir(path.join(directory, 'node_modules/native-target'), {
    recursive: true,
  });
  await writeFile(
    path.join(directory, 'node_modules/native-target/package.json'),
    JSON.stringify({
      name: 'native-target',
      version: '1.0.0',
      type: 'module',
      exports: './index.mjs',
    })
  );
  await writeFile(
    path.join(directory, 'node_modules/native-target/index.mjs'),
    'export function run() { return 42; }'
  );
  const probe = await file(
    'probe.mjs',
    `
    import { InstrumentationBase, InstrumentationNodeModuleDefinition } from '@opentelemetry/instrumentation';
    class Probe extends InstrumentationBase {
      constructor() { super('native-probe','1.0.0'); }
      init() { return new InstrumentationNodeModuleDefinition('native-target',['1.*'],exports=>{
        this._wrap(exports,'run',original=> (...args)=> { const span=this.tracer.startSpan('native-esm-probe');
          try { return original(...args); } finally { span.end(); } });
        return exports;
      }); }
    }
    new Probe();
  `
  );
  const native = await file(
    'native.mjs',
    `import {run} from 'native-target'; if(run()!==42) throw new Error('business result changed');`
  );
  for (const preexisting of [false, true]) {
    const before = received.length;
    const imports = [register, probe];
    if (preexisting) {
      const loader = await file(
        'loader.mjs',
        `import {register} from 'node:module'; register('@opentelemetry/instrumentation/hook.mjs', import.meta.url);`
      );
      imports.unshift(loader);
    }
    assert.deepEqual(await exited(launch(native, {}, imports)), {
      code: 0,
      signal: null,
    });
    const spans = received
      .slice(before)
      .filter(item => item.path === '/v1/traces')
      .flatMap(item => {
        return JSON.parse(item.body.toString()).resourceSpans.flatMap(
          resource => resource.scopeSpans.flatMap(scope => scope.spans)
        );
      });
    assert.equal(
      spans.filter(span => span.name === 'native-esm-probe').length,
      1
    );
  }
  passed.push(
    'Security-disabled native ESM exports are instrumented once, including an existing loader'
  );

  const app = await file(
    'app.cjs',
    `
    const http=require('node:http');
    const server=http.createServer((req,res)=>{ if(process.env.APP_DELAY) { console.log('REQUEST_ACTIVE'); setTimeout(()=>res.end('ok'),100); } else res.end('ok'); }).listen(0,'127.0.0.1',()=>{
      console.log('READY '+server.address().port);
      if(process.env.APP_REQUEST) http.get('http://127.0.0.1:'+server.address().port,res=>res.resume());
      if(process.env.APP_CLOSE) setTimeout(()=>server.close(),250);
    });
    if(process.env.APP_OWNS_SIGNAL) process.once('SIGINT',()=>{ console.log('APP_SIGNAL'); server.close(); });
  `
  );
  const beforeTags = received.length;
  assert.deepEqual(
    await exited(
      launch(app, {
        APP_REQUEST: 'true',
        APP_CLOSE: 'true',
        OTEL_PROFILING_ENABLED: 'true',
        OTEL_PROFILING_EXPORT_INTERVAL: '0.05',
      })
    ),
    { code: 0, signal: null }
  );
  const tagged = received.slice(beforeTags);
  assert.ok(
    tagged.some(
      item =>
        item.path === '/profiles' &&
        item.body.includes(Buffer.from('service:checkout')) &&
        item.body.includes(Buffer.from('version:v 1'))
    )
  );
  assert.ok(
    tagged
      .filter(item => item.path === '/v1/traces')
      .some(item =>
        JSON.parse(item.body.toString()).resourceSpans.some(resource =>
          resource.resource.attributes.some(
            attribute =>
              attribute.key === 'service.name' &&
              attribute.value.stringValue === 'checkout'
          )
        )
      )
  );
  passed.push(
    'packed trace and native profile service identity agree using only OTel resource attributes'
  );

  if (process.platform !== 'win32') {
    for (const owns of [false, true]) {
      const child = launch(app, {
        OTEL_PROFILING_ENABLED: 'true',
        ...(owns
          ? { APP_OWNS_SIGNAL: 'true', APP_REQUEST: 'true', APP_DELAY: 'true' }
          : {}),
      });
      await until(
        () => child.output.includes(owns ? 'REQUEST_ACTIVE' : 'READY'),
        child
      );
      child.kill('SIGINT');
      assert.deepEqual(
        await exited(child, 8000),
        owns ? { code: 0, signal: null } : { code: null, signal: 'SIGINT' }
      );
      if (owns) assert.equal(child.output.match(/APP_SIGNAL/g).length, 1);
    }
    passed.push(
      'first SIGINT terminates after cleanup and respects application-owned signal handlers'
    );
  }

  const [major, minor, patch] = process.versions.node.split('.').map(Number);
  const securitySupported =
    (major === 22 && (minor > 22 || (minor === 22 && patch >= 3))) ||
    (major === 24 && (minor > 11 || (minor === 11 && patch >= 1)));
  if (securitySupported && process.platform !== 'win32') {
    const pending = await file(
      'pending.mjs',
      `
      import express from 'express'; import fs from 'node:fs/promises';
      const app=express(); app.get('/pending',async(req,res)=>{
        try { await fs.readFile(req.query.path,'utf8'); } catch {}
        console.log('FINDING_READY'); await new Promise(()=>{});
      });
      const server=app.listen(0,'127.0.0.1',()=>console.log('READY '+server.address().port));
    `
    );
    const before = logs().length;
    const child = launch(pending, {
      BEACON_SECURITY_ENABLED: 'true',
      BEACON_SECURITY_NODE_INCLUDE: directory,
      BEACON_SECURITY_SBOM_ENABLED: 'false',
      OTEL_NODE_ENABLED_INSTRUMENTATIONS: 'http,express',
    });
    const port = await until(
      () => /READY (\d+)/.exec(child.output)?.[1],
      child
    );
    const request = http.get(
      `http://127.0.0.1:${port}/pending?path=${encodeURIComponent(pending)}`
    );
    request.on('error', () => {});
    try {
      await until(() => child.output.includes('FINDING_READY'), child);
      child.kill('SIGTERM');
      assert.deepEqual(await exited(child, 8000), {
        code: null,
        signal: 'SIGTERM',
      });
      assert.ok(
        logs()
          .slice(before)
          .some(
            event =>
              event.event_name === 'beacon.security.finding' &&
              event.rule === 'path_traversal' &&
              event.trace_id
          )
      );
    } finally {
      request.destroy();
    }
    passed.push(
      'SIGTERM ends active Security requests and exports OTLP findings before SDK Logs shutdown'
    );
  }
  console.log(JSON.stringify({ node: process.version, passed }, null, 2));
} finally {
  for (const child of children) child.kill('SIGKILL');
  receiver.closeAllConnections?.();
  await new Promise(resolve => receiver.close(resolve));
  await rm(directory, { recursive: true, force: true });
}
