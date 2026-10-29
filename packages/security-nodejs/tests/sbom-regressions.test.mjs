import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import test from 'node:test';
import { SbomInventory } from '../src/sbom/index.mjs';

process.env.BEACON_SECURITY_SBOM_REFRESH_SECONDS = '1';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(predicate, timeout = 10000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const value = predicate();
    if (value) return value;
    await sleep(10);
  }
  throw new Error('SBOM regression timeout');
}
async function write(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(
    file,
    typeof value === 'string' ? value : JSON.stringify(value)
  );
}

test('loaded package membership and attribution survive the default 4096 observation cap', async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), 'beacon-sbom-retention-')
  );
  const early = path.join(root, 'node_modules', 'early', 'index.mjs');
  const appFile = path.join(root, 'app.mjs');
  await write(path.join(root, 'package.json'), {
    name: 'app',
    version: '1.0.0',
  });
  await write(path.join(root, 'node_modules', 'early', 'package.json'), {
    name: 'early',
    version: '1.0.0',
  });
  await write(early, 'export default true;');
  await write(appFile, 'export default true;');
  const previous = process.env.BEACON_SECURITY_NODE_INCLUDE;
  process.env.BEACON_SECURITY_NODE_INCLUDE = root;
  const events = [];
  const inventory = new SbomInventory({ application_id: 'app' }, root, event =>
    events.push(event)
  );
  try {
    inventory.start();
    inventory.observe(pathToFileURL(early));
    await waitFor(() =>
      events.find(event =>
        event.dependencies?.some(item => item.name === 'early')
      )
    );
    const component = inventory.resolve(early);
    for (let i = 0; i < 4096; i++)
      inventory.observe(`${pathToFileURL(appFile).href}?version=${i}`);
    await waitFor(
      () =>
        inventory.published.byUrl[`${pathToFileURL(appFile).href}?version=4095`]
    );
    assert.equal(inventory.published.byPath[early], undefined);
    assert.deepEqual(inventory.resolve(early), component);
    const snapshot = events
      .filter(event => event.event_name === 'beacon.security.sbom.inventory')
      .at(-1);
    assert.ok(snapshot.dependencies.some(item => item.name === 'early'));
    assert.ok(inventory.droppedObservations > 0);
  } finally {
    await inventory.close();
    if (previous === undefined) delete process.env.BEACON_SECURITY_NODE_INCLUDE;
    else process.env.BEACON_SECURITY_NODE_INCLUDE = previous;
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('service-only npm workspace selectors resolve hoisted scoped dependencies and declared lock identities', async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), 'beacon-sbom-workspaces-')
  );
  const service = path.join(root, 'apps', 'api');
  const loaded = path.join(
    root,
    'node_modules',
    '@example',
    'early',
    'index.mjs'
  );
  await write(path.join(root, 'package.json'), {
    name: 'workspace',
    workspaces: ['apps/*'],
  });
  await write(path.join(service, 'package.json'), {
    name: 'api',
    version: '1.0.0',
    dependencies: { '@example/early': '1.0.0' },
  });
  await write(path.join(root, 'package-lock.json'), {
    lockfileVersion: 3,
    packages: {
      '': { name: 'workspace' },
      'node_modules/@example/early': { version: '1.0.0' },
      'node_modules/optional-missing': { version: '2.0.0', optional: true },
    },
  });
  await write(
    path.join(root, 'node_modules', '@example', 'early', 'package.json'),
    { name: '@example/early', version: '1.0.0' }
  );
  await write(loaded, 'export default true;');
  await write(path.join(root, 'node_modules', '.bin', 'tool'), 'tool');
  await write(path.join(root, 'node_modules', '.cache', 'data'), 'data');
  const messages = [];
  const output = path.join(root, 'output', 'application.cdx.json');
  const worker = new Worker(
    new URL('../src/sbom/worker.mjs', import.meta.url),
    {
      workerData: {
        include: [service],
        output,
        localOutputEnabled: true,
        identity: { application_id: 'api' },
      },
    }
  );
  worker.on('message', message => messages.push(message));
  try {
    worker.postMessage({ type: 'observe', value: pathToFileURL(loaded).href });
    worker.postMessage({ type: 'refresh' });
    const published = await waitFor(() =>
      messages.find(message => message.type === 'published')
    );
    assert.deepEqual(published.snapshot.application_roots, [service]);
    assert.ok(published.snapshot.byPath[loaded]['bom-ref']);
    assert.deepEqual(published.events[0].dependencies, [
      { name: '@example/early', version: '1.0.0' },
    ]);
    const document = JSON.parse(await fs.readFile(output, 'utf8'));
    assert.equal(
      document.properties
        .find(item => item.name === 'beacon:security:sbom:completeness-reasons')
        ?.value.includes('package_json_unreadable'),
      false
    );
    const optional = document.components.find(
      component => component.name === 'optional-missing'
    );
    assert.equal(optional.purl, 'pkg:npm/optional-missing@2.0.0');
  } finally {
    await worker.terminate();
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('unchanged periodic checks republish inventory without health events', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'beacon-sbom-idle-'));
  await write(path.join(root, 'package.json'), {
    name: 'idle',
    version: '1.0.0',
  });
  const messages = [];
  const worker = new Worker(
    new URL('../src/sbom/worker.mjs', import.meta.url),
    {
      workerData: {
        include: [root],
        identity: { application_id: 'idle' },
        settings: { refreshSeconds: 1 },
      },
    }
  );
  worker.on('message', message => messages.push(message));
  try {
    worker.postMessage({ type: 'refresh' });
    await waitFor(() => messages.some(message => message.type === 'published'));
    await sleep(1200);
    assert.ok(
      messages.filter(message => message.type === 'published').length >= 2
    );
    assert.equal(
      messages.filter(message => message.type === 'event').length,
      0
    );
    assert.ok(
      messages
        .filter(message => message.type === 'published')
        .every(message =>
          message.events.every(
            event => event.event_name === 'beacon.security.sbom.inventory'
          )
        )
    );
  } finally {
    await worker.terminate();
    await fs.rm(root, { recursive: true, force: true });
  }
});
