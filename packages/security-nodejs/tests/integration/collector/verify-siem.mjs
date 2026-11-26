import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

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
const evidenceSchema = ajv.compile(
  JSON.parse(
    await readFile(
      new URL('beacon-security-log-body-v1.schema.json', schemaRoot),
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
        const evidence = JSON.parse(log.body.stringValue);
        assert.equal(
          evidenceSchema(evidence),
          true,
          ajv.errorsText(evidenceSchema.errors)
        );
        assert.ok(!/[\r\n]/.test(log.body.stringValue));
        assert.ok(BigInt(log.timeUnixNano) > 0n);
        assert.equal(log.severityNumber, 9);
        const attributes = Object.fromEntries(
          (log.attributes || []).map(item => [item.key, item.value.stringValue])
        );
        assert.equal(attributes.source, evidence.source);
        assert.equal(attributes['event.name'], evidence.event_name);
        assert.ok(attributes.event_id);
        if (evidence.event_name === 'beacon.security.finding') {
          findings++;
          assert.ok(
            evidence.span_id,
            'real HTTP fixture must have an active invocation span'
          );
          assert.equal(log.traceId.toLowerCase(), evidence.trace_id);
          assert.equal(log.spanId.toLowerCase(), evidence.span_id);
        }
      }
    }
  }
}
assert.ok(findings > 0, 'collector must receive real Security findings');
console.log(
  `Validated ${findings} collector finding(s): compact Body schema, native metadata, invocation span, INFO and source attributes`
);
