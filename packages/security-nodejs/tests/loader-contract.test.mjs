import test, { after as afterTests } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import {
  GenMapping,
  addMapping,
  setSourceContent,
  toEncodedMap,
} from '@jridgewell/gen-mapping';

const here = dirname(fileURLToPath(import.meta.url));
const nodejsRoot = resolve(here, '..');
const require = createRequire(import.meta.url);
const registerPath = resolve(nodejsRoot, 'src/register.mjs');
const otelBootstrap = resolve(nodejsRoot, 'tests/fixtures/otel-bootstrap.mjs');
const observations = [];

function tagged(stdout, tag) {
  return stdout
    .split(/\r?\n/)
    .flatMap(line => {
      if (!line.startsWith(`${tag} `)) return [];
      try {
        return [JSON.parse(line.slice(tag.length + 1))];
      } catch {
        return [];
      }
    })
    .at(-1);
}

async function jsonFile(filename) {
  try {
    return JSON.parse(await readFile(filename, 'utf8'));
  } catch {
    return null;
  }
}

function diagnostic(child) {
  return `exit=${child.exitCode} signal=${child.signalCode}\nstdout=${child.stdout.slice(-3000)}\nstderr=${child.stderr.slice(-3000)}`;
}

async function runChild({
  root,
  script,
  extraArgs = [],
  envExtra = {},
  timeoutMillis = 30_000,
  withOtelBootstrap = true,
}) {
  const output = join(root, 'security-output');
  const environment = {
    ...process.env,
    BEACON_SECURITY_ENABLED: 'true',
    BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'true',
    BEACON_SECURITY_SBOM_ENABLED: 'true',
    BEACON_SECURITY_NODE_INCLUDE: root,
    BEACON_SECURITY_OUTPUT: output,
    BEACON_SECURITY_SBOM_REFRESH_SECONDS: '1',
    BEACON_SECURITY_QA_NODEJS_ROOT: nodejsRoot,
    NODE_OPTIONS: '',
    ...envExtra,
  };
  const args = [...extraArgs, '--import', registerPath];
  if (withOtelBootstrap) args.push('--import', otelBootstrap);
  args.push('--input-type=module', '--eval', script);
  const child = spawn(process.execPath, args, {
    cwd: nodejsRoot,
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => {
    child.stdoutText = (child.stdoutText || '') + chunk;
  });
  child.stderr.on('data', chunk => {
    child.stderrText = (child.stderrText || '') + chunk;
  });
  child.stdoutText = '';
  child.stderrText = '';
  const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMillis);
  await once(child, 'exit');
  clearTimeout(timer);
  child.stdout = { text: child.stdoutText };
  child.stderr = { text: child.stderrText };
  const health = await jsonFile(join(output, 'health.json'));
  const findings = await jsonFile(join(output, 'findings.json'));
  const sbom = await jsonFile(join(output, 'application.cdx.json'));
  return {
    exitCode: child.exitCode,
    signalCode: child.signalCode,
    stdout: child.stdoutText,
    stderr: child.stderrText,
    result: tagged(child.stdoutText, 'BEACON_SECURITY_QA_RESULT'),
    otel: tagged(child.stdoutText, 'BEACON_SECURITY_QA_OTEL'),
    health,
    findings,
    sbom,
    output,
  };
}

async function fixtureRoot(name) {
  const root = await mkdtemp(join(tmpdir(), `beacon_security-loader-${name}-`));
  await writeFile(
    join(root, 'package.json'),
    JSON.stringify({ name: `loader-${name}`, version: '1.0.0' })
  );
  return root;
}

async function writeExpressServer(root, importBlock, routeBody) {
  const source = `
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const require = createRequire(pathToFileURL(join(process.env.BEACON_SECURITY_QA_NODEJS_ROOT, 'package.json')));
const expressModule = require('express');
const express = expressModule.default || expressModule;
${importBlock}
export async function run(target) {
  const app = express();
  app.get('/probe', async (request, response, next) => {
    try {
      ${routeBody}
    } catch (error) {
      next(error);
    }
  });
  const server = await new Promise((resolve, reject) => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
    value.once('error', reject);
  });
  try {
    const response = await fetch(\`http://127.0.0.1:\${server.address().port}/probe?path=\${encodeURIComponent(target)}\`);
    return await response.json();
  } finally {
    await new Promise((resolve) => server.close(() => resolve()));
  }
}
`;
  const filename = join(root, 'server.mjs');
  await writeFile(filename, source);
  return pathToFileURL(filename).href;
}

function shutdownScript(resultExpression) {
  return `
const value = await (${resultExpression});
console.log('BEACON_SECURITY_QA_RESULT ' + JSON.stringify(value));
await globalThis.__securityQaShutdown?.({ timeoutMillis: 2500 });
`;
}

function findingEvents(result) {
  return result?.findings?.findings || [];
}

afterTests(async () => {
  const filename = process.env.BEACON_SECURITY_QA_LOADER_CONTRACT_RESULTS;
  if (!filename) return;
  await mkdir(dirname(filename), { recursive: true });
  await writeFile(
    filename,
    `${JSON.stringify({ schemaVersion: 1, node: process.version, tests: observations }, null, 2)}\n`
  );
});

test(
  'loader transforms query-distinct ESM modules and preserves cycles/live bindings',
  { concurrency: false },
  async () => {
    const root = await fixtureRoot('query-cycle');
    try {
      const cycleA = `
import { earlyRead, bValue } from './cycle-b.mjs';
export function hoisted() { return 'early-hoisted'; }
export const early = earlyRead();
export let liveValue = 'a-initial';
export function update(value) { liveValue = value; }
export function readLive() { return liveValue; }
export const fromB = bValue;
`;
      const cycleB = `
import { hoisted, liveValue } from './cycle-a.mjs';
export const bValue = 'b-stable';
export function earlyRead() { return hoisted(); }
export function readB() { return 'b-sees:' + liveValue; }
`;
      const business = `
import { readFile } from 'node:fs/promises';
import { early, fromB, readLive, update } from './cycle-a.mjs';
import { readB } from './cycle-b.mjs';
export const query = new URL(import.meta.url).search;
export const earlyValue = early;
export const cycleValue = fromB;
export function live() { return readLive(); }
export function mutate(value) { update(value); return readLive(); }
export function cycleLive() { return readB(); }
export async function probe(filename) { return await readFile(filename, 'utf8'); }
`;
      await writeFile(join(root, 'cycle-a.mjs'), cycleA);
      await writeFile(join(root, 'cycle-b.mjs'), cycleB);
      await writeFile(join(root, 'business.mjs'), business);
      const target = join(root, 'target.txt');
      await writeFile(target, 'loader-query-cycle\n');
      const serverUrl = await writeExpressServer(
        root,
        `import { query as leftQuery, earlyValue as leftEarly, cycleValue as leftCycle, live as leftLive, mutate as leftMutate, cycleLive as leftCycleLive, probe as leftProbe } from './business.mjs?case=left';
       import { query as rightQuery, live as rightLive, probe as rightProbe } from './business.mjs?case=right';`,
        `const content = await leftProbe(request.query.path);
       const before = leftLive();
       const changed = leftMutate('a-updated');
       const rightAfter = rightLive();
       const rightContent = await rightProbe(request.query.path);
       response.json({ content, rightContent, leftQuery, rightQuery, leftEarly, leftCycle, leftCycleLive: leftCycleLive(), before, changed, rightAfter });`
      );
      const child = await runChild({
        root,
        envExtra: {
          BEACON_SECURITY_QA_SERVER_URL: serverUrl,
          BEACON_SECURITY_QA_TARGET: target,
        },
        script: shutdownScript(
          `(await import(process.env.BEACON_SECURITY_QA_SERVER_URL)).run(process.env.BEACON_SECURITY_QA_TARGET)`
        ),
      });
      assert.equal(child.exitCode, 0, diagnostic(child));
      assert.deepEqual(child.result, {
        content: 'loader-query-cycle\n',
        rightContent: 'loader-query-cycle\n',
        leftQuery: '?case=left',
        rightQuery: '?case=right',
        leftEarly: 'early-hoisted',
        leftCycle: 'b-stable',
        leftCycleLive: 'b-sees:a-updated',
        before: 'a-initial',
        changed: 'a-updated',
        rightAfter: 'a-updated',
      });
      assert.ok(
        child.health?.counts?.transformed_modules >= 5,
        JSON.stringify(child.health)
      );
      const pathFindings = findingEvents(child).filter(
        event => event.rule === 'path_traversal'
      );
      assert.ok(pathFindings.length >= 1, JSON.stringify(child.findings));
      assert.ok(
        pathFindings.some(event =>
          event.representative?.sources?.some(
            source => source.type === 'http.request.parameter'
          )
        ),
        JSON.stringify(pathFindings)
      );
      assert.equal(child.otel?.securityApiAvailable, true, child.stderr);
      observations.push({
        name: 'query-cycle-live-binding',
        status: 'pass',
        transformedModules: child.health.counts.transformed_modules,
        findings: pathFindings.length,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
);

test(
  'external source map maps finding location while SBOM resolves compiled file',
  { concurrency: false },
  async () => {
    const root = await fixtureRoot('source-map');
    try {
      const original = join(root, 'mapped.ts');
      const originalText = `${Array.from({ length: 41 }, (_, index) => `// original ${index + 1}`).join('\n')}\nexport function read(filename) { return readFileSync(filename, 'utf8'); }\n`;
      await writeFile(original, originalText);
      const compiled = join(root, 'compiled.mjs');
      const map = new GenMapping({ file: 'compiled.mjs' });
      const source = pathToFileURL(original).href;
      for (let line = 1; line <= 4; line += 1)
        addMapping(map, {
          generated: { line, column: 0 },
          source,
          original: { line: 42, column: 0 },
        });
      setSourceContent(map, source, originalText);
      await writeFile(
        join(root, 'compiled.mjs.map'),
        JSON.stringify(toEncodedMap(map))
      );
      await writeFile(
        compiled,
        `import { readFileSync } from 'node:fs';\nexport function read(filename) {\n  return readFileSync(filename, 'utf8');\n}\n//# sourceMappingURL=compiled.mjs.map\n`
      );
      const target = join(root, 'mapped-target.txt');
      await writeFile(target, 'loader-source-map\n');
      const serverUrl = await writeExpressServer(
        root,
        `import { read } from './compiled.mjs';`,
        `const content = await read(request.query.path); response.json({ content });`
      );
      const child = await runChild({
        root,
        envExtra: {
          BEACON_SECURITY_QA_SERVER_URL: serverUrl,
          BEACON_SECURITY_QA_TARGET: target,
        },
        script: shutdownScript(
          `(await import(process.env.BEACON_SECURITY_QA_SERVER_URL)).run(process.env.BEACON_SECURITY_QA_TARGET)`
        ),
      });
      assert.equal(child.exitCode, 0, diagnostic(child));
      assert.deepEqual(child.result, { content: 'loader-source-map\n' });
      const pathFinding = findingEvents(child).find(
        event => event.rule === 'path_traversal'
      );
      assert.ok(pathFinding, JSON.stringify(child.findings));
      assert.match(
        pathFinding.sink.location,
        new RegExp(`${original.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}#42:`),
        JSON.stringify(pathFinding)
      );
      assert.equal(
        pathFinding.component?.status,
        'resolved',
        JSON.stringify(pathFinding)
      );
      assert.equal(
        pathFinding.component?.['bom-ref'],
        child.health?.identity?.application_id,
        JSON.stringify(pathFinding)
      );
      assert.ok(
        Number.isInteger(pathFinding.component?.revision) &&
          pathFinding.component.revision > 0,
        JSON.stringify(pathFinding)
      );
      assert.ok(
        pathFinding.component.revision <= child.health?.sbom?.revision,
        JSON.stringify({
          finding: pathFinding.component,
          sbom: child.health?.sbom,
        })
      );
      assert.equal(
        pathFinding.component?.sbom_id,
        child.health?.sbom?.sbom_id,
        JSON.stringify(pathFinding)
      );
      assert.ok(child.sbom?.metadata?.component, JSON.stringify(child.sbom));
      assert.equal(
        child.sbom.metadata.component['bom-ref'],
        child.health.identity.application_id
      );
      observations.push({
        name: 'external-source-map-sbom-component',
        status: 'pass',
        location: pathFinding.sink.location,
        revision: pathFinding.component.revision,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
);

test(
  'throwing business module executes once and transform limits retain native execution',
  { concurrency: false },
  async () => {
    const root = await fixtureRoot('limits');
    try {
      const sideEffect = join(root, 'side-effects.log');
      await writeFile(
        join(root, 'throw-once.mjs'),
        `import { appendFileSync } from 'node:fs';\nappendFileSync(process.env.BEACON_SECURITY_QA_SIDE_EFFECT, 'x');\nthrow new Error('loader-once');\n`
      );
      await writeFile(
        join(root, 'large.mjs'),
        `//${'x'.repeat(2 * 1024 * 1024)}\nexport const largeLoaded = true;\n`
      );
      await writeFile(
        join(root, 'dense.mjs'),
        Array.from(
          { length: 16000 },
          (_, index) => `const value${index} = ${index};`
        ).join('\n') + '\nexport const denseValue = value15999;\n'
      );
      const chain = Array.from({ length: 6000 }, (_, i) => `let value${i}=0;`)
        .concat(
          Array.from({ length: 5999 }, (_, i) => `value${i}=value${i + 1};`),
          "value5999='clean'; module.exports=value0;"
        )
        .join('\n');
      await writeFile(join(root, 'analysis.cjs'), chain);
      const transformed = (
        await import('../src/transform/index.mjs')
      ).transform(
        chain,
        join(root, 'analysis.cjs'),
        undefined,
        undefined,
        'commonjs'
      );
      assert.equal(transformed.code, chain);
      assert.ok(transformed.gaps.includes('transform_analysis_limit'));
      const child = await runChild({
        root,
        envExtra: {
          BEACON_SECURITY_QA_THROW_URL: pathToFileURL(
            join(root, 'throw-once.mjs')
          ).href,
          BEACON_SECURITY_QA_LARGE_URL: pathToFileURL(join(root, 'large.mjs'))
            .href,
          BEACON_SECURITY_QA_DENSE_URL: pathToFileURL(join(root, 'dense.mjs'))
            .href,
          BEACON_SECURITY_QA_ANALYSIS_URL: pathToFileURL(
            join(root, 'analysis.cjs')
          ).href,
          BEACON_SECURITY_QA_SIDE_EFFECT: sideEffect,
        },
        script: shutdownScript(`(async () => {
        const attempts = [];
        for (let index = 0; index < 2; index += 1) {
          try { await import(process.env.BEACON_SECURITY_QA_THROW_URL); } catch (error) { attempts.push(error.message); }
        }
        const loaded = await import(process.env.BEACON_SECURITY_QA_LARGE_URL);
        const dense = await import(process.env.BEACON_SECURITY_QA_DENSE_URL);
        const analysis = await import(process.env.BEACON_SECURITY_QA_ANALYSIS_URL);
        const sideEffect = await (await import('node:fs/promises')).readFile(process.env.BEACON_SECURITY_QA_SIDE_EFFECT, 'utf8');
        return { attempts, sideEffectCount: sideEffect.length, largeLoaded: loaded.largeLoaded, denseValue: dense.denseValue, analysisValue: analysis.default };
      })()`),
      });
      assert.equal(child.exitCode, 0, diagnostic(child));
      assert.deepEqual(child.result, {
        attempts: ['loader-once', 'loader-once'],
        sideEffectCount: 1,
        largeLoaded: true,
        denseValue: 15999,
        analysisValue: 0,
      });
      assert.ok(
        (child.health?.counts?.unmodeled_modules || 0) >= 1,
        JSON.stringify(child.health)
      );
      assert.ok(
        (child.health?.counts?.instrumentation_failures || 0) >= 1,
        JSON.stringify(child.health)
      );
      assert.ok(
        (child.health?.counts?.transformed_modules || 0) < 2,
        JSON.stringify(child.health)
      );
      observations.push({
        name: 'throw-once-source-limit',
        status: 'pass',
        instrumentationFailures: child.health.counts.instrumentation_failures,
        transformedModules: child.health.counts.transformed_modules,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
);

test(
  'legacy asynchronous IITM loader disables transform while private Proxy business still runs',
  { concurrency: false },
  async () => {
    const root = await fixtureRoot('legacy-loader');
    try {
      const module = join(root, 'private-proxy.mjs');
      await writeFile(
        module,
        `const privateValue = new Proxy({ value: 'proxy-ok' }, { get(target, key, receiver) { return Reflect.get(target, key, receiver); } });\nexport function check() { return privateValue.value; }\n`
      );
      const loader = require.resolve('import-in-the-middle/hook.mjs');
      const child = await runChild({
        root,
        extraArgs: ['--experimental-loader', loader],
        envExtra: { BEACON_SECURITY_QA_PROXY_URL: pathToFileURL(module).href },
        script: shutdownScript(
          `(await import(process.env.BEACON_SECURITY_QA_PROXY_URL)).check()`
        ),
      });
      assert.equal(child.exitCode, 0, diagnostic(child));
      assert.equal(child.result, 'proxy-ok');
      assert.equal(
        child.health?.configured,
        false,
        JSON.stringify(child.health)
      );
      assert.ok(
        (child.health?.counts?.transformed_modules || 0) === 0,
        JSON.stringify(child.health)
      );
      assert.ok(
        (child.health?.counts?.instrumentation_failures || 0) >= 1,
        JSON.stringify(child.health)
      );
      observations.push({
        name: 'legacy-iitm-loader-compatibility',
        status: 'pass',
        configured: child.health.configured,
        instrumentationFailures: child.health.counts.instrumentation_failures,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
);

test(
  'register naturally exits and writes health with SBOM both disabled and enabled',
  { concurrency: false },
  async () => {
    const results = [];
    for (const enabled of [false, true]) {
      const root = await fixtureRoot(
        `natural-exit-${enabled ? 'enabled' : 'disabled'}`
      );
      try {
        const module = join(root, 'natural.mjs');
        await writeFile(
          module,
          `export const marker = 'natural-exit-${enabled ? 'enabled' : 'disabled'}';\n`
        );
        const child = await runChild({
          root,
          withOtelBootstrap: false,
          timeoutMillis: 5_000,
          envExtra: {
            BEACON_SECURITY_SBOM_ENABLED: String(enabled),
            BEACON_SECURITY_QA_NATURAL_URL: pathToFileURL(module).href,
          },
          script: `const loaded = await import(process.env.BEACON_SECURITY_QA_NATURAL_URL); console.log('BEACON_SECURITY_QA_RESULT ' + JSON.stringify(loaded.marker));`,
        });
        assert.equal(
          child.exitCode,
          0,
          `sbom=${enabled}: ${diagnostic(child)}`
        );
        assert.equal(
          child.signalCode,
          null,
          `sbom=${enabled}: ${diagnostic(child)}`
        );
        assert.equal(
          child.result,
          `natural-exit-${enabled ? 'enabled' : 'disabled'}`
        );
        assert.equal(
          child.health?.event_name,
          'beacon.security.health',
          JSON.stringify(child)
        );
        assert.equal(
          child.health?.configured,
          true,
          JSON.stringify(child.health)
        );
        results.push({
          enabled,
          status: 'pass',
          healthStatus: child.health.status,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
    observations.push({
      name: 'natural-exit-sbom-toggle',
      status: 'pass',
      cases: results,
    });
  }
);
