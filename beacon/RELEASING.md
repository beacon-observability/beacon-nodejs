# Release Process

Beacon Node.js publishes fixed GitHub source releases independently from the
inherited OpenTelemetry package lifecycle. The
`@beacon-observability/profiler-nodejs` workspace remains private. Do not
publish inherited upstream packages or the profiler to npm from the current
repository state.

## Version Rules

- `beacon/version.properties` is the single manually maintained Beacon product
  version.
- The private profiler workspace version must match the Beacon product version;
  `node beacon/scripts/check-project.mjs` enforces this relationship.
- Development versions use `X.Y.Z-dev`, release candidates use `X.Y.Z-rc.N`,
  and official releases use `X.Y.Z` with a `beacon-vX.Y.Z` tag.
- Beacon product versions remain independent of inherited OpenTelemetry package
  versions and the pinned upstream commit.

Before a GitHub source release:

1. Pin the adopted upstream commit and all release inputs.
2. Update `beacon/version.properties`, the private profiler workspace version,
   lockfiles, and Beacon changelogs together.
3. Pass the declared Node.js runtime matrix and Beacon-specific regression
   tests.
4. Verify that inherited release workflows remain disabled and that the source
   release does not publish npm artifacts.
5. Publish an immutable `beacon-vX.Y.Z` source tag and document the validation
   scope and known limitations in the GitHub Release.

Publishing an npm package requires a separate release plan covering package
ownership, public naming, clean-install testing, receiver compatibility,
credentials, rollback, and installation acceptance.

## Candidate Validation

From a clean, fixed source commit:

```sh
node beacon/scripts/check-project.mjs
npm ci
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
npm pack --dry-run --workspace=@beacon-observability/profiler-nodejs
```

The package remains private, so this command only inspects a local candidate.
Compilation, tests, or `npm pack` do not constitute npm publication or
receiver acceptance. Record the source commit, dependency lockfile, candidate
digest, runtime matrix, and known limitations together.

If a tag or artifact differs from the accepted candidate, stop the release and
use a new version after correcting and revalidating it. Never overwrite a
published version.

Only publish installation instructions after validating installation from an
actual public artifact.
