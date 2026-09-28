# CI and Repository Checks

[`Beacon Node.js CI`](../.github/workflows/beacon-ci.yml) is the maintained
validation entry for pushes to `main`, pull requests targeting `main`, and
manual runs. It is restricted to `beacon-observability/beacon-nodejs` and uses
read-only repository permissions.

## Beacon Matrix

The workflow runs the Beacon project check, installs the committed lockfile,
and compiles and tests the private profiler workspace on Node.js 18.19, 20, 22,
and 24. The Node.js 24 job also checks repository formatting, Markdown,
release-please package metadata, and both example lockfiles.

This matrix validates the Beacon-specific workspace only. It does not replace
the complete upstream instrumentation, browser, service-integration, or
all-versions matrices and does not establish production support for every
runtime in the matrix.

## Inherited Workflow Isolation

All inherited OpenTelemetry workflows are disabled in the Beacon GitHub
repository. Only the Beacon workflow may be enabled after review. Upstream
release, dependency-update, scheduled, issue-management, and organization-
specific workflows are not Beacon publication or maintenance entry points.

After every upstream synchronization, review newly added or renamed workflow
files before enabling any Actions event. Repository conditions and missing
secrets are not substitutes for disabling an unadapted publication workflow.

## Required Local Checks

Run from the repository root:

```sh
node beacon/scripts/check-project.mjs
npm ci
npm run compile --workspace=@beacon-observability/profiler-nodejs
npm test --workspace=@beacon-observability/profiler-nodejs
npm run lint:prettier
npm run lint:markdown
npm run lint:release-please
```

Passing CI produces development evidence only. It does not publish artifacts or
replace runtime, ingestion, performance, upgrade, or rollback acceptance.
