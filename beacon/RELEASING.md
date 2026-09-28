# Release Process

Beacon Node.js publishes fixed GitHub source releases and the Beacon-owned
`@beacon-observability/profiler-nodejs` package. Inherited OpenTelemetry
packages retain their upstream identities and must not be published by Beacon.

## Version Rules

- `beacon/version.properties` is the single manually maintained Beacon product
  version.
- The profiler workspace version must match the Beacon product version;
  `node beacon/scripts/check-project.mjs` enforces this relationship.
- Development versions use `X.Y.Z-dev`, release candidates use `X.Y.Z-rc.N`,
  and official releases use `X.Y.Z` with a `beacon-vX.Y.Z` tag.
- Beacon product versions remain independent of inherited OpenTelemetry package
  versions and the pinned upstream commit.

Before a release:

1. Pin the adopted upstream commit and all release inputs.
2. Update `beacon/version.properties`, the profiler workspace version,
   `profiler_version` resource tag, lockfiles, and Beacon changelogs together.
3. Pass the declared Node.js runtime matrix and Beacon-specific regression
   tests.
4. Inspect the exact npm package contents and install the packed tarball in a
   clean application outside the repository.
5. Verify that inherited release workflows remain disabled and that only the
   Beacon-owned profiler is in the npm publication scope.
6. Publish the profiler version once, then publish the immutable
   `beacon-vX.Y.Z` source tag and matching GitHub Release.

## Candidate Validation

From a clean, fixed source commit:

```sh
node beacon/scripts/check-project.mjs
npm ci
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
npm pack --dry-run --workspace=@beacon-observability/profiler-nodejs
npm publish --dry-run --workspace=@beacon-observability/profiler-nodejs
```

Compilation, tests, packing, or dry-run publication do not constitute receiver
acceptance. Record the source commit, dependency lockfile, candidate digest,
runtime matrix, and known limitations together.

If a tag or artifact differs from the accepted candidate, stop the release and
use a new version after correcting and revalidating it. Never overwrite a
published version.

After publication, install the exact public version from npm in a clean
application, verify the exported API, and confirm that the GitHub tag resolves
to the published package source commit.
