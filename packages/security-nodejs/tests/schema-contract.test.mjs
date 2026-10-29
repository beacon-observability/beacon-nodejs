import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

import {
  FINGERPRINT_VERSION,
  PRODUCT,
  SCHEMA_VERSION,
  eventRecord,
  onlineEvent,
  findingFingerprint,
  sinkFields,
} from '../src/schema.mjs';

const fixtures = resolve(
  dirname(fileURLToPath(import.meta.url)),
  'fixtures/spec'
);
const vectors = JSON.parse(
  await readFile(resolve(fixtures, 'fingerprint-v1.json'), 'utf8')
);
const schema = JSON.parse(
  await readFile(
    resolve(fixtures, 'beacon-security-event-v2.schema.json'),
    'utf8'
  )
);
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
});
addFormats(ajv);
const validateEvent = ajv.compile(schema);

function assertSchema(value) {
  assert.equal(
    validateEvent(value),
    true,
    ajv.errorsText(validateEvent.errors)
  );
}

const identity = {
  application_id:
    'app-dc6b8b0dc435531262eedacdf8fe51bd619964caa0e12bb4c29477448fdda8ae',
  instance_id: '11111111-1111-4111-8111-111111111111',
  service: { 'service.name': 'orders' },
  code: { repository: '', commit: '', build_id: '', service_version: '' },
  runtime: {
    language: 'javascript',
    implementation: 'nodejs',
    version: process.versions.node,
    os: process.platform,
    architecture: process.arch,
    details: {},
  },
  identity_status: 'configured',
};

test('pins Beacon Security schema v2 and fingerprint v1', () => {
  assert.equal(SCHEMA_VERSION, 2);
  assert.equal(FINGERPRINT_VERSION, 1);
  assert.equal(PRODUCT, 'io.beacon.security');
  assert.equal(vectors.fingerprint_version, 1);
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
});

test('passes every shared fingerprint v1 vector', () => {
  for (const vector of vectors.vectors) {
    const { input } = vector;
    assert.equal(
      findingFingerprint(
        input.application_id,
        input.language,
        input.rule,
        input.sink,
        input.source_signatures
      ),
      vector.expected,
      vector.name
    );
  }
});

test('normalizes sink aliases to canonical dimensions', () => {
  assert.deepEqual(
    sinkFields(
      'path_traversal',
      'source',
      'node:fs.readFile',
      'file:///srv/files.mjs:10:1'
    ),
    {
      function: 'node:fs.readFile',
      role: 'file_path',
      location: 'file:///srv/files.mjs:10:1',
      operation: 'read',
      path_role: 'source',
      input_part: '',
    }
  );
});

test('emits only the Beacon v2 finding and inventory envelopes', () => {
  const finding = onlineEvent(
    eventRecord(
      {
        event_name: 'beacon.security.finding',
        occurrence_id: 'ev-node-test',
        finding_id: `finding-${'a'.repeat(64)}`,
        fingerprint_version: 1,
        rule: 'sql_injection',
        precision: 'exact',
        attack_evidence: { status: 'unknown', reason: 'analysis_unavailable' },
        request: { method: 'GET', route: '/orders', status_code: 200 },
        sink: sinkFields(
          'sql_injection',
          'sql_template',
          'mysql2.Connection.query',
          'file:///srv/orders.mjs:20:1'
        ),
        component: { name: 'orders', version: '1.0.0' },
        evidence_sampled: true,
        collection_complete: true,
      },
      identity
    )
  );
  assert.equal(finding.schema_version, 2);
  assert.equal(finding.source, 'beacon_security');
  assert.equal(finding.event_name, 'beacon.security.finding');
  assert.equal(finding.instance_id, identity.instance_id);
  assert.equal(Object.hasOwn(finding, 'application_id'), false);
  assertSchema(finding);

  const inventory = onlineEvent(
    eventRecord(
      {
        event_name: 'beacon.security.sbom.inventory',
        started_at: '2026-10-27T09:00:00.000Z',
        uptime_ms: 1200000,
        dependencies: [],
      },
      identity
    )
  );
  assert.equal(inventory.schema_version, 2);
  assert.equal(inventory.source, 'beacon_security_sbom');
  assert.equal(inventory.event_name, 'beacon.security.sbom.inventory');
  assertSchema(inventory);
});
