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
        event => event.event_name === 'beacon.security.sbom.snapshot'
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
      assert.equal(snapshot.revision, 1);
      assert.deepEqual(snapshot.dependencies, [
        { name: 'trusted-pkg', version: '2.0.0' },
      ]);
      const resolvedPackage = inventory.resolve(
        `${pathToFileURL(packageFile).href}?cache=1`
      );
      const resolvedApp = inventory.resolve(
        `${pathToFileURL(appFile).href}?source=loader`
      );
      assert.equal(resolvedPackage.status, 'resolved');
      assert.equal(resolvedPackage['bom-ref'], component['bom-ref']);
      assert.equal(resolvedPackage.revision, snapshot.revision);
      assert.equal(resolvedPackage.query, '?cache=1');
      assert.equal(resolvedApp['bom-ref'], 'app-fixture');
      const history = JSON.parse(
        await fs.readFile(path.join(output, 'sbom-history.json'), 'utf8')
      );
      assert.equal(history.revision, snapshot.revision);
      assert.equal(history.sbom_id, snapshot.sbom_id);
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
      { sbom_id: 'fixture', revision: 3 },
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
          event.event_name === 'beacon.security.sbom.snapshot' &&
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
        assert.equal(
          inventory.resolve(pathToFileURL(filename))['bom-ref'],
          component['bom-ref']
        );
      }
      assert.equal(
        inventory.resolve(`${pathToFileURL(alias).href}?alias=1`)['bom-ref'],
        inventory.resolve(pathToFileURL(files[1].filename))['bom-ref']
      );
      await fs.unlink(files[1].filename);
      inventory.worker.postMessage({ type: 'refresh' });
      const updated = await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.snapshot' &&
          event.reasons.includes('observed_file_unreadable')
      );
      assert.deepEqual(updated.dependencies, [
        { name: 'trusted-pkg', version: '2.0.0' },
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
  'a snapshot that cannot fit its envelope does not commit a local revision',
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
      await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.update_failed'
      );
      const health = await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.health' &&
          event.status === 'degraded'
      );
      assert.equal(health.revision, 0);
      await assert.rejects(
        fs.readFile(path.join(output, 'application.cdx.json')),
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
    }
  }
);

test(
  'keeps unsupported package-manager state incomplete and resolves app roots from the published snapshot',
  { concurrency: false },
  async () => {
    const { root, appFile } = await fixture();
    await fs.writeFile(
      path.join(root, 'pnpm-lock.yaml'),
      'lockfileVersion: 9\n'
    );
    const output = path.join(root, 'output');
    withEnvironment(root, output);
    const events = [];
    const inventory = new SbomInventory(
      { application_id: 'app-pnpm' },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      const snapshot = await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.snapshot'
      );
      assert.ok(snapshot.reasons.includes('pnpm_lock_unsupported'));
      const appRootFile = path.join(root, 'startup-handler.mjs');
      const resolvedAppRoot = inventory.resolve(
        pathToFileURL(appRootFile).href
      );
      assert.equal(resolvedAppRoot.status, 'resolved');
      assert.equal(resolvedAppRoot['bom-ref'], 'app-pnpm');
      assert.equal(resolvedAppRoot.revision, snapshot.revision);
      const outsideFile = path.join(
        path.dirname(root),
        'outside-sbom-file.mjs'
      );
      assert.equal(
        inventory.resolve(pathToFileURL(outsideFile).href).status,
        'unresolved'
      );
      inventory.observe('https://example.invalid/module.mjs');
      assert.equal(
        inventory.resolve('https://example.invalid/module.mjs').reason,
        'unsupported_url_scheme'
      );
      inventory.observe(pathToFileURL(appFile));
      await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.snapshot' &&
          event.revision > snapshot.revision
      );
      assert.equal(
        inventory.resolve(pathToFileURL(appFile)).status,
        'resolved'
      );
    } finally {
      await inventory.close();
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
    }
  }
);

test(
  'reports bounded observation loss without changing the last published revision',
  { concurrency: false },
  async () => {
    const { root, appFile } = await fixture();
    const output = path.join(root, 'output');
    withEnvironment(root, output, { BEACON_SECURITY_SBOM_MAX_ENTRIES: '100' });
    const events = [];
    const inventory = new SbomInventory(
      { application_id: 'app-queue' },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      const first = await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.snapshot'
      );
      const before = inventory.resolve(pathToFileURL(appFile).href);
      assert.equal(before.revision, first.revision);

      const appUrl = pathToFileURL(appFile).href;
      for (let index = 0; index < 4096; index += 1)
        inventory.observe(`${appUrl}?observation=${index}`);

      const health = await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.health' &&
          event.dropped_observations > 0
      );
      assert.ok(health.dropped_observations > 0);
      assert.ok(health.reasons.includes('observation_queue_full'));
      const second = await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.snapshot' &&
          event.revision > first.revision
      );
      assert.equal(second.dropped_observations > 0, true);
      const after = inventory.resolve(pathToFileURL(appFile).href);
      assert.equal(before.revision, first.revision);
      assert.equal(after.revision, second.revision);
      assert.equal(after.status, 'resolved');
    } finally {
      await inventory.close();
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
      delete process.env.BEACON_SECURITY_SBOM_MAX_ENTRIES;
    }
  }
);

test(
  'worker termination emits one failure and keeps the last snapshot usable through close',
  { concurrency: false },
  async () => {
    const { root, appFile } = await fixture();
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
      const snapshot = await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.snapshot'
      );
      const before = inventory.resolve(pathToFileURL(appFile).href);
      assert.equal(before.revision, snapshot.revision);
      const worker = inventory.worker;
      assert.ok(worker);
      await worker.terminate();
      await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.update_failed'
      );
      const health = await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.health' &&
          event.status === 'degraded'
      );
      assert.equal(health.revision, snapshot.revision);
      assert.deepEqual(inventory.resolve(pathToFileURL(appFile).href), before);
      await inventory.close(100);
      await new Promise(resolve => setTimeout(resolve, 30));
      assert.equal(
        events.filter(
          event => event.event_name === 'beacon.security.sbom.update_failed'
        ).length,
        1
      );
      assert.equal(
        events.filter(
          event => event.event_name === 'beacon.security.sbom.snapshot'
        ).length,
        1
      );
    } finally {
      await inventory.close(100);
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
    }
  }
);

test(
  'healthy close settles after a published observation without a late failure',
  { concurrency: false },
  async () => {
    const { root, appFile } = await fixture();
    const output = path.join(root, 'output');
    withEnvironment(root, output);
    const events = [];
    const inventory = new SbomInventory(
      { application_id: 'app-healthy-close' },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      const first = await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.snapshot'
      );
      inventory.observe(`${pathToFileURL(appFile).href}?close=drain`);
      const second = await waitFor(
        events,
        event =>
          event.event_name === 'beacon.security.sbom.snapshot' &&
          event.revision > first.revision
      );
      assert.equal(
        inventory.resolve(pathToFileURL(appFile).href).revision,
        second.revision
      );
      await inventory.close(1000);
      await new Promise(resolve => setTimeout(resolve, 30));
      assert.equal(inventory.worker, null);
      assert.equal(
        events.filter(
          event => event.event_name === 'beacon.security.sbom.update_failed'
        ).length,
        0
      );
      assert.equal(
        events.filter(
          event => event.event_name === 'beacon.security.sbom.snapshot'
        ).length,
        2
      );
    } finally {
      await inventory.close(100);
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
    }
  }
);

test(
  'close publishes loader observations that are still waiting for the batch timer',
  { concurrency: false },
  async () => {
    const { root } = await fixture();
    const output = path.join(root, 'close-flush-output');
    withEnvironment(root, output, {
      BEACON_SECURITY_SBOM_REFRESH_SECONDS: '300',
    });
    const events = [];
    const inventory = new SbomInventory(
      { application_id: 'app-close-flush' },
      output,
      event => events.push(event)
    );
    try {
      inventory.start();
      const first = await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.snapshot'
      );
      const lateRoot = path.join(root, 'node_modules', 'trusted-pkg');
      const lateFile = path.join(lateRoot, 'index.mjs');
      await fs.writeFile(lateFile, 'export default true;\n');

      inventory.observe(`${pathToFileURL(lateFile).href}?shutdown=immediate`);
      await inventory.close(2500);

      const document = JSON.parse(
        await fs.readFile(path.join(output, 'application.cdx.json'), 'utf8')
      );
      const component = document.components.find(
        item => item.name === 'trusted-pkg' && item.version === '2.0.0'
      );
      assert.ok(component);
      assert.equal(
        component.properties.find(
          item => item.name === 'beacon:security:sbom:loaded'
        )?.value,
        'true'
      );
      assert.ok(document.serialNumber);
      assert.equal(document.version, first.revision + 1);
      const resolved = inventory.resolve(pathToFileURL(lateFile));
      assert.equal(resolved.status, 'resolved');
      assert.equal(resolved['bom-ref'], component['bom-ref']);
      assert.equal(resolved.revision, document.version);
      assert.equal(
        events.filter(
          event => event.event_name === 'beacon.security.sbom.update_failed'
        ).length,
        0
      );
    } finally {
      await inventory.close(100);
      delete process.env.BEACON_SECURITY_NODE_INCLUDE;
      delete process.env.BEACON_SECURITY_SBOM_OUTPUT;
      delete process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS;
      await fs.rm(root, { recursive: true, force: true });
    }
  }
);

test(
  'history preserves unchanged entries and retries failed updates before removal and restoration',
  { concurrency: false },
  async () => {
    const { root } = await fixture();
    const output = path.join(root, 'history-output');
    const build = path.join(root, 'build.cdx.json');
    const first = {
      type: 'library',
      'bom-ref': 'first',
      name: 'first',
      version: '1',
      licenses: [{ license: { name: 'MIT' } }],
    };
    const second = {
      type: 'library',
      'bom-ref': 'second',
      name: 'second',
      version: '1',
    };
    const write = components =>
      fs.writeFile(
        build,
        JSON.stringify({
          bomFormat: 'CycloneDX',
          specVersion: '1.7',
          components,
        })
      );
    await write([first]);
    withEnvironment(root, output, {
      BEACON_SECURITY_SBOM_BUILD_FILE: build,
      BEACON_SECURITY_SBOM_REFRESH_SECONDS: '300',
    });
    const events = [];
    const inventory = new SbomInventory(
      { application_id: 'history-test' },
      output,
      event => events.push(event)
    );
    const history = async () =>
      JSON.parse(
        await fs.readFile(path.join(output, 'sbom-history.json'), 'utf8')
      );
    const document = async () =>
      JSON.parse(
        await fs.readFile(path.join(output, 'application.cdx.json'), 'utf8')
      );
    const entry = (value, ref) =>
      value.entries.find(row => row['bom-ref'] === ref);
    const refresh = async () => {
      events.length = 0;
      inventory.worker.postMessage({ type: 'refresh' });
      return waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.health'
      );
    };
    try {
      inventory.start();
      await waitFor(
        events,
        event => event.event_name === 'beacon.security.sbom.snapshot'
      );
      const ref = (await document()).components.find(
        row => row.name === 'first'
      )['bom-ref'];
      const initial = entry(await history(), ref);
      assert.equal((await refresh()).revision, 1);
      await write([first, second]);
      assert.equal((await refresh()).revision, 2);
      assert.deepEqual(entry(await history(), ref), initial);
      first.licenses = [{ license: { name: 'Apache-2.0' } }];
      await write([first, second]);
      const previous = await history();
      await fs.rename(output, output + '-saved');
      await fs.writeFile(output, 'blocked directory');
      assert.equal((await refresh()).revision, 2);
      assert.ok(
        events.some(
          event => event.event_name === 'beacon.security.sbom.update_failed'
        )
      );
      await fs.unlink(output);
      await fs.rename(output + '-saved', output);
      assert.deepEqual(await history(), previous);
      assert.equal((await refresh()).revision, 3);
      assert.deepEqual(
        (await document()).components.find(row => row.name === 'first')
          .licenses,
        first.licenses
      );
      await write([second]);
      assert.equal((await refresh()).revision, 4);
      assert.equal(entry(await history(), ref).state, 'removed');
      await write([first, second]);
      assert.equal((await refresh()).revision, 5);
      const restored = entry(await history(), ref);
      assert.equal(restored.state, 'current');
      assert.equal(restored.first_seen, initial.first_seen);
    } finally {
      await inventory.close();
      for (const key of [
        'BEACON_SECURITY_NODE_INCLUDE',
        'BEACON_SECURITY_SBOM_OUTPUT',
        'BEACON_SECURITY_SBOM_REFRESH_SECONDS',
        'BEACON_SECURITY_SBOM_BUILD_FILE',
      ])
        delete process.env[key];
      await fs.rm(root, { recursive: true, force: true });
    }
  }
);
