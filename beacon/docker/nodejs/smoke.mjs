import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const bundle = process.argv[2] || '/opt/beacon-nodejs';
const version = process.argv[3];
const sbomEvent =
  Number(version?.split('.')[0]) >= 2
    ? 'beacon.security.sbom.inventory'
    : 'beacon.security.sbom.snapshot';
const json = path => JSON.parse(readFileSync(path, 'utf8'));
assert(version, 'Usage: node smoke.mjs <bundle-directory> <version>');
assert.equal(process.getuid(), 65532);
assert.equal(process.versions.node.split('.')[0], '24');
const manifest = json(join(bundle, 'metadata/release/release-manifest.json'));
const provenance = json(join(bundle, 'metadata/provenance.json'));
assert.equal(provenance.version, version);
assert.equal(
  createHash('sha256')
    .update(readFileSync(join(bundle, 'package-lock.json')))
    .digest('hex'),
  provenance.dependency_lock_sha256
);
for (const item of manifest.items) {
  assert.equal(
    json(join(bundle, 'node_modules', item.name, 'package.json')).version,
    version
  );
  assert.equal(
    createHash('sha256')
      .update(readFileSync(join(bundle, 'metadata/release', item.file)))
      .digest('hex'),
    item.sha256
  );
  for (const file of item.files) {
    assert(file.startsWith('package/') && !file.split('/').includes('..'));
    assert.deepEqual(
      readFileSync(
        join(bundle, 'node_modules', item.name, file.slice('package/'.length))
      ),
      execFileSync('tar', [
        '-xOf',
        join(bundle, 'metadata/release', item.file),
        file,
      ]),
      `Installed release file differs: ${item.name}/${file}`
    );
  }
}
const received = [];
const receiver = http.createServer((request, response) => {
  const chunks = [];
  request.on('data', chunk => chunks.push(chunk));
  request.on('end', () => {
    received.push({
      path: request.url,
      contentType: request.headers['content-type'] || '',
      body: Buffer.concat(chunks),
    });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{}');
  });
});
await new Promise(resolve => receiver.listen(0, '127.0.0.1', resolve));
const endpoint = `http://127.0.0.1:${receiver.address().port}`;
const scratch = mkdtempSync('/tmp/beacon-image-smoke-');
try {
  for (const esm of [false, true]) {
    received.length = 0;
    let output = '';
    const child = spawn(process.execPath, [join(here, 'fixture.cjs')], {
      cwd: scratch,
      env: {
        ...process.env,
        NODE_OPTIONS: esm
          ? `--import=${bundle}/node_modules/@beacon-observability/nodejs/register.mjs`
          : `--require=${bundle}/node_modules/@beacon-observability/nodejs/build/src/register.js`,
        OTEL_SERVICE_NAME: 'beacon-nodejs-image-smoke',
        OTEL_NODE_ENABLED_INSTRUMENTATIONS: 'http',
        OTEL_NODE_RESOURCE_DETECTORS: 'env',
        OTEL_EXPORTER_OTLP_PROTOCOL: 'http/json',
        OTEL_EXPORTER_OTLP_ENDPOINT: endpoint,
        OTEL_TRACES_EXPORTER: 'otlp',
        OTEL_METRICS_EXPORTER: 'none',
        OTEL_LOGS_EXPORTER: esm ? 'otlp' : 'none',
        OTEL_BSP_SCHEDULE_DELAY: '100',
        OTEL_BLRP_SCHEDULE_DELAY: '100',
        OTEL_PROFILING_ENABLED: String(esm),
        OTEL_PROFILING_EXPORT_INTERVAL: '1',
        OTEL_PROFILING_PPROF_UPLOAD_URL: `${endpoint}/profiles`,
        BEACON_SECURITY_ENABLED: String(esm),
        BEACON_SECURITY_NODE_INCLUDE: here,
        BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'false',
        BEACON_SECURITY_OUTPUT: join(scratch, 'security-output'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', chunk => {
      output += chunk;
    });
    child.stderr.on('data', chunk => {
      output += chunk;
    });
    const timer = setTimeout(() => child.kill('SIGKILL'), 45000);
    const [code, signal] = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code, signal) => resolve([code, signal]));
    });
    clearTimeout(timer);
    assert.equal(code, 0, `${signal}\n${output}`);
    const traceparent =
      /TRACEPARENT (00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2})/.exec(
        output
      )?.[1];
    assert(traceparent, output);
    const traces = received
      .filter(item => item.path === '/v1/traces')
      .map(item => JSON.parse(item.body));
    const resources = traces.flatMap(item => item.resourceSpans || []);
    const spans = resources.flatMap(resource =>
      (resource.scopeSpans || []).flatMap(scope => scope.spans || [])
    );
    assert(
      resources.some(resource =>
        resource.resource.attributes.some(
          attr =>
            attr.key === 'service.name' &&
            attr.value.stringValue === 'beacon-nodejs-image-smoke'
        )
      )
    );
    assert(
      spans.filter(
        span => span.traceId.toLowerCase() === traceparent.split('-')[1]
      ).length >= 2,
      'Expected correlated client/server spans'
    );
    assert(
      spans.some(
        span => span.parentSpanId?.toLowerCase() === traceparent.split('-')[2]
      ),
      'Expected propagated parent span'
    );
    const profiles = received.filter(item => item.path === '/profiles');
    const logs = received.filter(item => item.path === '/v1/logs');
    if (esm) {
      assert(
        profiles.some(
          item =>
            item.contentType.includes('multipart/form-data') &&
            item.body.includes(Buffer.from('wall.pprof')) &&
            item.body.includes(Buffer.from('beacon-nodejs-image-smoke'))
        ),
        `No native profile: ${output}`
      );
      assert(
        logs.some(item => item.body.includes(Buffer.from(sbomEvent))),
        `No Security SBOM: ${output}`
      );
    } else {
      assert.equal(profiles.length, 0);
      assert.equal(logs.length, 0);
    }
    assert(
      !existsSync(join(scratch, 'security-output')),
      'Local Security output must remain disabled'
    );
    console.log(
      `PASS: ${esm ? 'ESM, native profiles and Security SBOM' : 'CommonJS, optional features disabled'}; correlated OTLP traces; Beacon ${version}; ${process.arch}; non-root.`
    );
  }
} finally {
  await new Promise(resolve => receiver.close(resolve));
  rmSync(scratch, { recursive: true, force: true });
}
