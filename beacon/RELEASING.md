# Release Prerequisites

Beacon Node.js has no official release process yet. The
`@beacon-observability/profiler-nodejs` workspace is private and development
examples use the local workspace package. Do not publish inherited upstream
packages or the profiler from the current repository state.

## Version Rules

- `beacon/version.properties` is the single manually maintained Beacon product
  version.
- The private profiler workspace version must match the Beacon product version;
  `node beacon/scripts/check-project.mjs` enforces this relationship.
- Development versions use `X.Y.Z-dev`, release candidates use `X.Y.Z-rc.N`,
  and official releases use `X.Y.Z` with a `beacon-vX.Y.Z` tag.
- Beacon product versions remain independent of inherited OpenTelemetry package
  versions and the pinned upstream commit.

Before an initial release:

1. Confirm package ownership, public names, maintainers, and publication
   permissions.
2. Pin the validated upstream commit and all release inputs.
3. Define the first artifact set and the required or optional relationship
   between instrumentation and profiling.
4. Pass the declared Node.js runtime matrix, Beacon-specific regression tests,
   the relevant upstream matrix, and clean-install tests from candidate
   artifacts.
5. Validate telemetry against the actual receiver and document compatible
   protocols, versions, limitations, and rollback procedures.
6. Separate ordinary CI permissions from release credentials and adapt or
   replace inherited release workflows.
7. Publish immutable artifacts and a fixed source tag, then reinstall from the
   public channel and repeat acceptance checks.

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
Compilation, tests, or `npm pack` do not constitute publication or ingestion
acceptance. Record the source commit, dependency lockfile, candidate digest,
runtime matrix, known limitations, and rollback procedure together.

If a tag or artifact differs from the accepted candidate, stop the release and
use a new version after correcting and revalidating it. Never overwrite a
published version.

Only after those steps pass should the product repository receive a fixed
installation guide and GitHub Release link.
