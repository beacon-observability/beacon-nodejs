import assert from 'node:assert/strict';

// The image workflow also verifies immutable releases. Select the wire contract
// from the installed candidate, not from the source checkout running the smoke.
export function profileContract(exporters) {
  if (typeof exporters.OtlpProfilingExporter === 'function') {
    return {
      path: '/v1development/profiles',
      environment: endpoint => ({
        OTEL_PROFILING_EXPORTER: 'otlp',
        OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT: `${endpoint}/v1development/profiles`,
        OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL: 'http/protobuf',
      }),
      matches: request => request.contentType === 'application/x-protobuf',
    };
  }
  assert.equal(
    typeof exporters.HttpProfilingExporter,
    'function',
    'Candidate does not expose a recognized profiling exporter'
  );
  return {
    path: '/profiles',
    environment: endpoint => ({
      OTEL_PROFILING_PPROF_UPLOAD_URL: `${endpoint}/profiles`,
    }),
    matches: request =>
      request.contentType.includes('multipart/form-data') &&
      request.body.includes(Buffer.from('wall.pprof')) &&
      request.body.includes(Buffer.from('event.json')),
  };
}
