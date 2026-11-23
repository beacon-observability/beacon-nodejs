import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { siemEvent } from '../../../src/siem.mjs';

const ajv = new Ajv2020({
  strict: true,
  strictTypes: false,
  strictRequired: false,
});
addFormats(ajv);
const schemaRoot = new URL(
  '../../fixtures/spec/current/schemas/',
  import.meta.url
);
const envelopeSchema = ajv.compile(
  JSON.parse(
    await readFile(
      new URL('beacon-security-siem-v1.schema.json', schemaRoot),
      'utf8'
    )
  )
);
const evidenceSchema = ajv.compile(
  JSON.parse(
    await readFile(
      new URL('beacon-security-event-v2.schema.json', schemaRoot),
      'utf8'
    )
  )
);
const input = await readFile(process.argv[2], 'utf8');
let findings = 0;
for (const line of input.trim().split('\n')) {
  const batch = JSON.parse(line);
  for (const resource of batch.resourceLogs || []) {
    for (const scope of resource.scopeLogs || []) {
      if (scope.scope?.name !== 'io.beacon.security') continue;
      for (const log of scope.logRecords || []) {
        const envelope = JSON.parse(log.body.stringValue);
        assert.equal(
          envelopeSchema(envelope),
          true,
          ajv.errorsText(envelopeSchema.errors)
        );
        const evidence = JSON.parse(envelope.message);
        assert.equal(
          evidenceSchema(evidence),
          true,
          ajv.errorsText(evidenceSchema.errors)
        );
        assert.deepEqual(
          envelope,
          siemEvent(envelope.message, {
            'service.name': envelope.service,
            'tenant.id': envelope.tenant_id,
          })
        );
        assert.equal(log.severityNumber, 9);
        const attributes = Object.fromEntries(
          (log.attributes || []).map(item => [item.key, item.value.stringValue])
        );
        assert.equal(attributes.source, envelope.source);
        assert.equal(attributes['event.name'], evidence.event_name);
        if (envelope.event_class === 'security_finding') {
          findings++;
          assert.ok(
            envelope.span_id,
            'real HTTP fixture must have an active invocation span'
          );
          assert.equal(log.traceId.toLowerCase(), envelope.trace_id);
          assert.equal(log.spanId.toLowerCase(), envelope.span_id);
          assert.equal(envelope.span_id, evidence.span_id);
        }
      }
    }
  }
}
assert.ok(findings > 0, 'collector must receive real Security findings');
console.log(
  `Validated ${findings} collector finding(s): SIEM and v2 schemas, mapping, invocation span, INFO and source attributes`
);
