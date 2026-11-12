/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

const assert = require('node:assert/strict');
const { describe, it } = require('mocha');
const { gzipSync } = require('node:zlib');
const { mkdtemp, readdir, readFile, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { createServer } = require('node:http');
const grpc = require('@grpc/grpc-js');
const {
  Profile,
  Function: PprofFunction,
  Line,
  Location,
  Mapping,
  Sample,
  StringTable,
  ValueType,
} = require('pprof-format');
const {
  OtlpProfilingExporter,
  FileProfilingExporter,
} = require('../src/exporter');
const { profilesRequest, profilesResponse } = require('../src/otlp');
function batch() {
  return {
    startTime: new Date('2026-04-13T07:40:02.123Z'),
    endTime: new Date('2026-04-13T07:40:04.456Z'),
    family: 'nodejs',
    format: 'pprof',
    tags: { service: 'checkout', env: 'prod' },
    profiles: [
      {
        type: 'wall',
        filename: 'wall.pprof',
        data: Buffer.from(
          gzipSync(
            makeProfile({
              sampleTypes: [
                ['cpu', 'nanoseconds', 20],
                ['wall', 'nanoseconds', 30],
              ],
            }).encode()
          )
        ),
      },
    ],
  };
}
function verify(bytes) {
  const request = profilesRequest.toObject(profilesRequest.decode(bytes), {
    longs: String,
  });
  const dictionary = request.dictionary;
  const resource = request.resourceProfiles[0];
  assert(
    resource.resource.attributes.some(
      a => a.key === 'service.name' && a.value.stringValue === 'checkout'
    )
  );
  const profiles = resource.scopeProfiles[0].profiles;
  assert.equal(profiles.length, 2);
  assert.deepEqual(
    profiles.map(p => p.samples[0].values),
    [['20'], ['30']]
  );
  assert.equal(profiles[0].timeUnixNano, '1776066002123000000');
  const stack = dictionary.stackTable[profiles[0].samples[0].stackIndex];
  const location = dictionary.locationTable[stack.locationIndices[0]];
  const fn = dictionary.functionTable[location.lines[0].functionIndex];
  assert.equal(dictionary.stringTable[fn.nameStrindex], 'handler');
  assert.equal(dictionary.stringTable[fn.filenameStrindex], 'app.js');
  assert.equal(location.lines[0].line, '1');
  assert(!profiles[0].originalPayload);
}

describe('profiling exporters', () => {
  it('sends a real OTLP HTTP/protobuf request', async () => {
    let received;
    const server = createServer(async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      received = {
        path: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks),
      };
      res.writeHead(200, { 'Content-Type': 'application/x-protobuf' });
      res.end();
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const exporter = new OtlpProfilingExporter({
        endpoint: `http://127.0.0.1:${server.address().port}/v1development/profiles`,
        headers: { tenant: 'demo' },
      });
      await exporter.export(batch());
      assert.equal(received.path, '/v1development/profiles');
      assert.equal(received.headers['content-type'], 'application/x-protobuf');
      assert.equal(received.headers.tenant, 'demo');
      verify(received.body);
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
  });
  it('sends the same OTLP payload over a real gRPC service', async () => {
    let received;
    const server = new grpc.Server();
    server.addService(
      {
        export: {
          path: '/opentelemetry.proto.collector.profiles.v1development.ProfilesService/Export',
          requestStream: false,
          responseStream: false,
          requestDeserialize: value => value,
          requestSerialize: value => value,
          responseDeserialize: value => value,
          responseSerialize: value => value,
        },
      },
      {
        export(call, callback) {
          received = call.request;
          assert.equal(call.metadata.get('tenant')[0], 'demo');
          callback(null, Buffer.alloc(0));
        },
      }
    );
    const port = await new Promise((resolve, reject) =>
      server.bindAsync(
        '127.0.0.1:0',
        grpc.ServerCredentials.createInsecure(),
        (error, port) => (error ? reject(error) : resolve(port))
      )
    );
    const exporter = new OtlpProfilingExporter({
      endpoint: `http://127.0.0.1:${port}`,
      protocol: 'grpc',
      headers: { tenant: 'demo' },
    });
    try {
      await exporter.export(batch());
      verify(received);
    } finally {
      await exporter.shutdown();
      await new Promise(resolve => server.tryShutdown(resolve));
    }
  });
  it('rejects HTTP failures and OTLP partial rejection', async () => {
    const exporter = new OtlpProfilingExporter({
      endpoint: 'http://localhost:4318/v1development/profiles',
      fetch: async () => new Response('', { status: 400 }),
    });
    await assert.rejects(
      exporter.export(batch()),
      /profiling export failed: 400/
    );
    const partial = profilesResponse
      .encode(
        profilesResponse.fromObject({
          partialSuccess: { rejectedProfiles: 1, errorMessage: 'bad profile' },
        })
      )
      .finish();
    const rejected = new OtlpProfilingExporter({
      endpoint: 'http://localhost:4318/profiles',
      fetch: async () => new Response(partial, { status: 200 }),
    });
    await assert.rejects(rejected.export(batch()), /rejected 1 profiles/);
  });
  it('writes pprof files without an endpoint', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'beacon-profile-'));
    try {
      await new FileProfilingExporter({ directory }).export(batch());
      const files = await readdir(directory);
      assert.equal(files.length, 1);
      assert(files[0].endsWith('.pprof'));
      assert.deepEqual(
        await readFile(join(directory, files[0])),
        batch().profiles[0].data
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
function makeProfile({ sampleTypes }) {
  const strings = new StringTable();
  const fn = new PprofFunction({
    id: 1,
    name: strings.dedup('handler'),
    systemName: strings.dedup('handler'),
    filename: strings.dedup('app.js'),
    startLine: 1,
  });
  const mapping = new Mapping({
    id: 1,
    hasFunctions: true,
    hasFilenames: true,
    hasLineNumbers: true,
    hasInlineFrames: true,
  });
  const location = new Location({
    id: 1,
    mappingId: 1,
    address: 1,
    line: [
      new Line({
        functionId: 1,
        line: 1,
      }),
    ],
  });

  return new Profile({
    sampleType: sampleTypes.map(
      ([type, unit]) =>
        new ValueType({
          type: strings.dedup(type),
          unit: strings.dedup(unit),
        })
    ),
    sample: [
      new Sample({
        locationId: [1],
        value: sampleTypes.map(([, , value]) => value),
      }),
    ],
    mapping: [mapping],
    location: [location],
    function: [fn],
    stringTable: strings,
    timeNanos: 1n,
    durationNanos: 10n,
  });
}
