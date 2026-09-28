# Upstream Synchronization

Beacon Node.js preserves the complete official OpenTelemetry JavaScript Contrib
history. The exact adopted baseline is recorded in
[`upstream.lock.json`](upstream.lock.json).

## Remotes

Use the Beacon repository as `origin` and the official project as `upstream`:

```sh
git remote add upstream https://github.com/open-telemetry/opentelemetry-js-contrib.git
git fetch --tags upstream
```

Confirm the configured URLs before fetching or pushing. A local remote name is
not part of the repository's reproducible state.

## Synchronization Procedure

1. Fetch `upstream/main` and its tags.
2. Record the exact target commit before merging. When the maintenance request
   is to adopt the latest upstream source, use the current `upstream/main` head
   at the start of the synchronization, not an unfixed future branch state.
3. Review upstream dependency, runtime, workflow, and release changes.
4. Merge the selected commit into a dedicated synchronization branch while
   preserving upstream history.
5. Resolve conflicts without overwriting Beacon-specific packages or enabling
   inherited publication behavior.
6. Regenerate lockfiles with the repository's declared npm version and run the
   affected compile, test, lint, and example checks.
7. Update `upstream.lock.json` only after validation passes, then record gaps and
   compatibility impact in the synchronization pull request or release notes.

An upstream merge is not an official Beacon release. Failed validation keeps
the previously adopted baseline authoritative.

## Workflow Safety

Inherited GitHub Actions are disabled when this repository is created. Each
workflow must have an identified Beacon consumer, suitable permissions, and
reviewed secrets and publication targets before it is enabled. In particular,
upstream release automation must not publish packages on behalf of Beacon.
