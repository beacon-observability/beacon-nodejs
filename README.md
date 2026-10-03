# Beacon Node.js

Beacon Node.js is a Node.js instrumentation and enhancement project built from
the complete OpenTelemetry JavaScript Contrib source tree. This standalone
downstream repository preserves the official upstream history while maintaining
Beacon-specific features, tests, versions, and release processes independently.

The source tree is preparing Beacon Node.js `1.2.0`; the current public stable
version remains `1.1.0` until npm and GitHub release acceptance completes.
Users install the public `@beacon-observability/nodejs` package for zero-code
auto-instrumentation and optional profiling and Security. Inherited
OpenTelemetry packages keep their original names, versions, and release
lifecycles and are not republished by Beacon.

The repository includes the public `@beacon-observability/nodejs` product
package and `@beacon-observability/profiler-nodejs` profiling component. The
product package preloads standard OpenTelemetry Node.js auto-instrumentation
and can optionally collect wall and heap profiles through the profiler. The
profiling component exports a compatible `pprof` layout and is not an
implementation of the OpenTelemetry Profiles signal.

After the `1.2.0` release completes, install the exact product version with:

```sh
npm install @beacon-observability/nodejs@1.2.0
```

Run an unchanged application through the zero-code preload entry point:

```sh
NODE_OPTIONS="--require @beacon-observability/nodejs/register" \
OTEL_SERVICE_NAME="my-node-service" \
OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:4317" \
OTEL_EXPORTER_OTLP_PROTOCOL="grpc" \
node app.js
```

An OTLP/HTTP receiver on `http://127.0.0.1:9529` can be selected with
`OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` or `http/json`, according to the
receiver's supported protocol.

## Development Resources

- [Development guide and project boundaries](beacon/README.md)
- [Source provenance and adopted upstream baseline](beacon/upstream.lock.json)
- [OpenTelemetry synchronization process](beacon/UPSTREAM.md)
- [CI scope and workflow isolation](beacon/CI.md)
- [Release process](beacon/RELEASING.md)
- [Beacon product changelog](beacon/CHANGELOG.md)
- [Verified Beacon-specific contributors](beacon/CONTRIBUTORS.md)
- [Beacon Node.js npm workspace](packages/nodejs/)
- [Profiler workspace](packages/profiler-nodejs/)
- [Zero-code injection example](examples/zero-code-demo/)
- [OTLP trace validation example](examples/validation-demo/)
- [Contribution guide](CONTRIBUTING.md)

The primary development branch is `main`. Run the following commands from the
repository root for the maintained Beacon-specific checks:

```sh
node beacon/scripts/check-project.mjs
npm ci
npm run compile --workspace=@beacon-observability/nodejs
npm test --workspace=@beacon-observability/nodejs
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
node beacon/scripts/zero-code-smoke.mjs
```

The dedicated Beacon CI runs these checks on Node.js 18.19, 20, 22, and 24.
The Node.js 24 job also validates repository formatting, Markdown, package
metadata, and example lockfiles.

This CI scope covers the Beacon-owned product package, zero-code entry point,
and profiler workspace. It does not replace the complete upstream browser,
service-integration, or all-versions matrices. A successful build or test run
does not constitute profiling receiver compatibility or npm package acceptance.

## Beacon Contributors

<p align="center">
  <a href="https://github.com/lrwh">
    <img src="https://avatars.githubusercontent.com/u/17264378?v=4" width="96" height="96" alt="Reid Liu">
    <br>
    Reid Liu
  </a>
</p>

## Product and Upstream Projects

- [Beacon product repository](https://github.com/beacon-observability/beacon)
- [OpenTelemetry JavaScript Contrib](https://github.com/open-telemetry/opentelemetry-js-contrib)
- [OpenTelemetry JavaScript core](https://github.com/open-telemetry/opentelemetry-js)
- [Adopted upstream commit](https://github.com/open-telemetry/opentelemetry-js-contrib/commit/31b2af9dd5fcc5f96949e5666f8f45b30b997722)

This repository preserves the upstream source layout, Git history, package
names, [license](LICENSE), and third-party attribution. Only Beacon-owned
packages use the Beacon name. Upstream `@opentelemetry/*` packages retain their
original identity and independent release lifecycle.
