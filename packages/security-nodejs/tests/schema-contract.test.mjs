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
    resolve(fixtures, 'beacon-security-event-v1.schema.json'),
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
  instance_id: 'node-test-instance',
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

test('pins Beacon Security schema and fingerprint version 1', () => {
  assert.equal(SCHEMA_VERSION, 1);
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

test('emits the Beacon v1 finding and SBOM envelopes', () => {
  const finding = eventRecord(
    {
      event_name: 'beacon.security.finding',
      evidence_id: 'ev-node-test',
      finding_id: `finding-${'a'.repeat(64)}`,
      fingerprint_version: 1,
      rule: 'sql_injection',
      assessment: 'candidate_risk',
      validation: 'unvalidated',
      severity: 'unassigned',
      confidence: 'modeled_flow',
      execution_observation: 'invocation_attempt',
      precision: 'exact',
      trace_id: '',
      server_span_id: '',
      current_span_id: '',
      trace_flags: 0,
      sources: [],
      propagation: [],
      ranges: [],
      sink: sinkFields(
        'sql_injection',
        'sql_template',
        'mysql2.Connection.query',
        'file:///srv/orders.mjs:20:1'
      ),
      truncated: false,
      coverage: 'modeled_calls_only',
      coverage_gaps: [],
      request: {},
      component: {},
      stack: [],
    },
    identity
  );
  assert.equal(finding.schema_version, 1);
  assert.equal(finding.source, 'beacon_security');
  assert.equal(finding.event_name, 'beacon.security.finding');
  assert.equal(finding.application_id, identity.application_id);
  assert.equal(finding.runtime.language, 'javascript');
  assertSchema(finding);

  const snapshot = eventRecord(
    {
      event_name: 'beacon.security.sbom.snapshot',
      sbom_id: 'urn:uuid:node-test',
      revision: 1,
      release_id: 'release-node-test',
      status: 'current',
      completeness: 'incomplete',
      reasons: ['runtime_dependency_graph_incomplete'],
      component_count: 0,
      part_index: 0,
      part_count: 1,
      dependencies: [],
    },
    identity
  );
  assert.equal(snapshot.schema_version, 1);
  assert.equal(snapshot.source, 'beacon_security_sbom');
  assert.equal(snapshot.event_name, 'beacon.security.sbom.snapshot');
  assertSchema(snapshot);
});
