import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

import { SbomInventory } from '../src/sbom/index.mjs';
import { dependencySnapshot } from '../src/sbom/snapshot.mjs';

async function fixture() {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), 'beacon_security-node-sbom-')
  );
  await fs.mkdir(path.join(root, 'node_modules', 'trusted-pkg'), {
    recursive: true,
  });
  await fs.writeFile(
    path.join(root, 'package.json'),
    JSON.stringify({
      name: 'fixture-app',
      version: '1.0.0',
      dependencies: { 'trusted-pkg': '2.0.0' },
    })
  );
  await fs.writeFile(
    path.join(root, 'package-lock.json'),
    JSON.stringify({
      name: 'fixture-app',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'fixture-app',
          version: '1.0.0',
          dependencies: { 'trusted-pkg': '2.0.0' },
        },
        'node_modules/trusted-pkg': {
          name: 'trusted-pkg',
          version: '2.0.0',
          integrity: 'sha512-declared-only',
        },
      },
    })
  );
  await fs.writeFile(
    path.join(root, 'node_modules', 'trusted-pkg', 'package.json'),
    JSON.stringify({
      name: 'trusted-pkg',
      version: '2.0.0',
      license: 'MIT',
    })
  );
  const appFile = path.join(root, 'app.mjs');
  const packageFile = path.join(
    root,
    'node_modules',
    'trusted-pkg',
    'package.json'
  );
  await fs.writeFile(appFile, 'export default true;\n');
  return { root, appFile, packageFile };
}

async function waitFor(events, predicate, timeout = 2500) {
  const started = Date.now();
  while (Date.now() - started < timeout) {
    const found = events.find(predicate);
    if (found) return found;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error('timed out waiting for SBOM event');
}

function withEnvironment(root, output, extra = {}) {
  process.env.BEACON_SECURITY_NODE_INCLUDE = root;
  process.env.BEACON_SECURITY_LOCAL_OUTPUT_ENABLED = 'true';
  process.env.BEACON_SECURITY_SBOM_OUTPUT = output;
  process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS = '1';
  for (const [key, value] of Object.entries(extra)) process.env[key] = value;
}

test(
  'publishes a real npm lock graph without treating lock integrity as local hash',
  { concurrency: false },
  async () => {
    const { root, appFile, packageFile } = await fixture();
    const output = path.join(root, 'output');
    withEnvironment(root, output);
    const events = [];
    const inventory = new SbomInventory(
      {
        application_id: 'app-fixture',
        instance_id: 'instance-fixture',
        service: { 'service.name': 'fixture-app' },
        code: {},
        runtime: {},
        identity_status: 'configured',
      },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      inventory.observe(`${pathToFileURL(packageFile).href}?cache=1`);
      inventory.observe(`${pathToFileURL(appFile).href}?source=loader`);
      const snapshot = await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.inventory'
      );
      const document = JSON.parse(
        await fs.readFile(path.join(output, 'application.cdx.json'), 'utf8')
      );
      const component = document.components.find(
        entry => entry.purl === 'pkg:npm/trusted-pkg@2.0.0'
      );
      assert.equal(document.bomFormat, 'CycloneDX');
      assert.equal(document.specVersion, '1.7');
      assert.ok(component);
      assert.equal(component.hashes, undefined);
      assert.equal(
        component.properties.find(
          item => item.name === 'beacon:security:sbom:integrity-status'
        ).value,
        'declared'
      );
      assert.equal(
        component.properties.find(
          item => item.name === 'beacon:security:sbom:authenticity-status'
        ).value,
        'unverified'
      );
      assert.equal(
        component.properties.find(
          item => item.name === 'beacon:security:sbom:identity-status'
        ).value,
        'incomplete'
      );
      assert.ok(
        document.dependencies.some(
          edge =>
            edge.ref === 'app-fixture' &&
            edge.dependsOn.includes(component['bom-ref'])
        )
      );
      assert.equal(document.metadata.component['bom-ref'], 'app-fixture');
      assert.equal(snapshot.schema_version, 2);
      assert.deepEqual(snapshot.dependencies, [
        { name: 'trusted-pkg', version: '2.0.0' },
      ]);
      const resolvedPackage = inventory.resolve(
        `${pathToFileURL(packageFile).href}?cache=1`
      );
      const resolvedApp = inventory.resolve(
        `${pathToFileURL(appFile).href}?source=loader`
      );
      assert.deepEqual(resolvedPackage, {
        name: 'trusted-pkg',
        version: '2.0.0',
      });
      assert.deepEqual(resolvedApp, { name: 'fixture-app', version: '' });
      assert.equal(document.version, 1);
      await assert.rejects(fs.access(path.join(output, 'sbom-history.json')), {
        code: 'ENOENT',
      });
    } finally {
      await inventory.close();
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
    }
  }
);

test('compact snapshots split by encoded bytes and retain only loaded package identities', () => {
  const previous = process.env.BEACON_SECURITY_EVIDENCE_MAX_BYTES;
  process.env.BEACON_SECURITY_EVIDENCE_MAX_BYTES = '2048';
  try {
    const records = Array.from({ length: 150 }, (_, index) => ({
      type: 'library',
      name: `@scope/package-${index}-中文`,
      version: '1.0',
      purl: `pkg:npm/pkg-${index}`,
      properties: [{ name: 'beacon:security:sbom:loaded', value: 'true' }],
    }));
    const fallback = {
      type: 'library',
      name: 'unknown',
      hashes: [{ alg: 'SHA-256', content: 'abcd' }],
      properties: records[0].properties,
    };
    records.push(fallback, fallback, {
      type: 'library',
      name: 'not-loaded',
      version: '2.0',
    });
    const parts = dependencySnapshot(
      { instance_id: '11111111-1111-4111-8111-111111111111' },
      records,
      {}
    );
    assert.ok(parts.length > 1);
    for (const [index, part] of parts.entries()) {
      assert.ok(Buffer.byteLength(JSON.stringify(part)) <= 2048);
      assert.equal(part.part_index, index);
      assert.equal(part.part_count, parts.length);
    }
    const dependencies = parts.flatMap(part => part.dependencies);
    assert.equal(dependencies.length, 151);
    assert.deepEqual(
      dependencies.find(row => row.name === 'unknown'),
      { name: 'unknown', version: '', hash: 'abcd' }
    );
    assert.deepEqual(dependencySnapshot({}, [], {})[0].dependencies, []);
  } finally {
    if (previous === undefined)
      delete process.env.BEACON_SECURITY_EVIDENCE_MAX_BYTES;
    else process.env.BEACON_SECURITY_EVIDENCE_MAX_BYTES = previous;
  }
});

test(
  'loaded modules resolve to the closest package root across nesting and symlinks',
  { concurrency: false },
  async () => {
    const { root } = await fixture();
    const parent = path.join(root, 'node_modules', 'trusted-pkg');
    const nested = path.join(parent, 'node_modules', 'trusted-pkg');
    const sibling = path.join(root, 'node_modules', 'trusted-pkg-extra');
    const output = path.join(root, 'output');
    const files = [];
    for (const [directory, name, version] of [
      [parent, 'trusted-pkg', '2.0.0'],
      [nested, 'trusted-pkg', '3.0.0'],
      [sibling, 'trusted-pkg-extra', '4.0.0'],
    ]) {
      await fs.mkdir(directory, { recursive: true });
      await fs.writeFile(
        path.join(directory, 'package.json'),
        JSON.stringify({ name, version })
      );
      const filename = path.join(directory, 'index.mjs');
      await fs.writeFile(filename, 'export default true;\n');
      files.push({ filename, name, version });
    }
    const alias = path.join(root, 'nested-alias.mjs');
    await fs.symlink(files[1].filename, alias);
    withEnvironment(root, output);
    const events = [];
    const inventory = new SbomInventory(
      { application_id: 'app-nested' },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      for (const { filename } of files)
        inventory.observe(pathToFileURL(filename));
      inventory.observe(`${pathToFileURL(alias).href}?alias=1`);
      await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.inventory' &&
          event.dependencies.length === 3
      );
      const document = JSON.parse(
        await fs.readFile(path.join(output, 'application.cdx.json'), 'utf8')
      );
      for (const { filename, name, version } of files) {
        const component = document.components.find(
          item => item.name === name && item.version === version
        );
        assert.ok(component);
        assert.deepEqual(inventory.resolve(pathToFileURL(filename)), {
          name,
          version,
        });
      }
      assert.deepEqual(
        inventory.resolve(`${pathToFileURL(alias).href}?alias=1`),
        inventory.resolve(pathToFileURL(files[1].filename))
      );
      await fs.unlink(files[1].filename);
      inventory.worker.postMessage({ type: 'refresh' });
      const updated = await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.inventory' &&
          event.observed_at !== events[0].observed_at
      );
      assert.deepEqual(updated.dependencies, [
        { name: 'trusted-pkg', version: '2.0.0' },
        // Removing a loaded module's on-disk file does not unload its code
        // from this process. Keep observed membership and report unreadability.
        { name: 'trusted-pkg', version: '3.0.0' },
        { name: 'trusted-pkg-extra', version: '4.0.0' },
      ]);
    } finally {
      await inventory.close();
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
      await fs.rm(root, { recursive: true, force: true });
    }
  }
);

test(
  'an inventory that exceeds its byte limit does not replace the last result',
  { concurrency: false },
  async () => {
    const { root } = await fixture();
    const output = path.join(root, 'output');
    const previous = process.env.BEACON_SECURITY_EVIDENCE_MAX_BYTES;
    withEnvironment(root, output, { BEACON_SECURITY_EVIDENCE_MAX_BYTES: '1' });
    const events = [];
    const inventory = new SbomInventory(
      { application_id: 'app-small-envelope' },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      const started = Date.now();
      while (!inventory.lastFailure && Date.now() - started < 2500)
        await new Promise(resolve => setTimeout(resolve, 10));
      assert.equal(
        inventory.lastFailure,
        'dependency_snapshot_envelope_exceeds_budget'
      );
      assert.deepEqual(events, []);
      await assert.rejects(
        fs.access(path.join(output, 'application.cdx.json')),
        { code: 'ENOENT' }
      );
    } finally {
      await inventory.close();
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
      if (previous === undefined)
        delete process.env.BEACON_SECURITY_EVIDENCE_MAX_BYTES;
      else process.env.BEACON_SECURITY_EVIDENCE_MAX_BYTES = previous;
      await fs.rm(root, { recursive: true, force: true });
    }
  }
);

test(
  'unknown URLs stay unresolved while application roots use direct metadata',
  { concurrency: false },
  async () => {
    const { root, appFile } = await fixture();
    const output = path.join(root, 'output');
    withEnvironment(root, output);
    const events = [];
    const inventory = new SbomInventory(
      {
        application_id: 'app-root',
        service: { 'service.name': 'fixture-app' },
      },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.inventory'
      );
      assert.deepEqual(inventory.resolve(pathToFileURL(appFile)), {
        name: 'fixture-app',
        version: '',
      });
      assert.equal(
        inventory.resolve('https://example.invalid/module.mjs'),
        null
      );
      assert.equal(
        inventory.resolve(
          pathToFileURL(path.join(path.dirname(root), 'outside.mjs'))
        ),
        null
      );
    } finally {
      await inventory.close();
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
      await fs.rm(root, { recursive: true, force: true });
    }
  }
);

test(
  'worker termination retains the last component map without a failure event',
  { concurrency: false },
  async () => {
    const { root, packageFile } = await fixture();
    const output = path.join(root, 'output');
    withEnvironment(root, output);
    const events = [];
    const inventory = new SbomInventory(
      { application_id: 'app-worker-stop' },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      inventory.observe(pathToFileURL(packageFile));
      await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.inventory' &&
          event.dependencies.length === 1
      );
      const before = inventory.resolve(pathToFileURL(packageFile));
      assert.deepEqual(before, { name: 'trusted-pkg', version: '2.0.0' });
      const count = events.length;
      await inventory.worker.terminate();
      await new Promise(resolve => setTimeout(resolve, 30));
      assert.equal(events.length, count);
      assert.deepEqual(inventory.resolve(pathToFileURL(packageFile)), before);
    } finally {
      await inventory.close(100);
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
      await fs.rm(root, { recursive: true, force: true });
    }
  }
);
