# Beacon Node.js

Beacon Node.js is a Node.js instrumentation and enhancement project built from
the complete OpenTelemetry JavaScript Contrib source tree. This standalone
downstream repository preserves the official upstream history while maintaining
Beacon-specific features, tests, versions, and release processes independently.

The current Beacon product version is `0.1.0`. This release fixes a reproducible
source baseline for Beacon Node.js; it does not republish the inherited
OpenTelemetry packages or provide a public npm package. Inherited OpenTelemetry
packages keep their original names, versions, and release lifecycles.

The repository currently includes an experimental private
`@beacon-observability/profiler-nodejs` workspace. It collects Node.js wall and
heap profiles, maps OpenTelemetry resource attributes to profiling tags, and
can export receiver-compatible `pprof` payloads. This package is a practical
profiling bridge and is not an implementation of the OpenTelemetry Profiles
signal.

## Development Resources

- [Development guide and project boundaries](beacon/README.md)
- [Source provenance and adopted upstream baseline](beacon/upstream.lock.json)
- [OpenTelemetry synchronization process](beacon/UPSTREAM.md)
- [CI scope and workflow isolation](beacon/CI.md)
- [Release process](beacon/RELEASING.md)
- [Beacon product changelog](beacon/CHANGELOG.md)
- [Verified Beacon-specific contributors](beacon/CONTRIBUTORS.md)
- [Profiler workspace](packages/profiler-nodejs/)
- [OTLP trace validation example](examples/validation-demo/)
- [Contribution guide](CONTRIBUTING.md)

The primary development branch is `main`. Run the following commands from the
repository root for the maintained Beacon-specific checks:

```sh
node beacon/scripts/check-project.mjs
npm ci
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
```

The dedicated Beacon CI has passed these checks on Node.js 18.19, 20, 22, and
24. The Node.js 24 job also validates repository formatting, Markdown, package
metadata, and example lockfiles. See the
[initial Beacon CI run](https://github.com/beacon-observability/beacon-nodejs/actions/runs/36390660551)
for the recorded result.

This CI scope covers Beacon-owned entry points and the profiler workspace. It
does not replace the complete upstream instrumentation, browser,
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
