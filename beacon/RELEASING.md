# Release Prerequisites

Beacon Node.js has no official release process yet. The
`@beacon-observability/profiler-nodejs` workspace is private and development
examples use the local workspace package. Do not publish inherited upstream
packages or the profiler from the current repository state.

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

Only after those steps pass should the product repository receive a fixed
installation guide and GitHub Release link.
