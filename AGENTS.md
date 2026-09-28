# Repository Collaboration Rules

- Always communicate with users in Simplified Chinese.
- Write Beacon product and development documentation in English.
- Read `CONTRIBUTING.md` before changing inherited packages, and use
  `beacon/README.md` for Beacon-specific boundaries and validation entry points.
- Preserve the complete OpenTelemetry JavaScript Contrib history and layout.
- Keep Beacon-specific changes isolated, tested, and documented under `beacon/`.
- Distinguish inherited upstream behavior, implemented Beacon changes, validated
  behavior, and planned work. Do not turn examples into support claims.
- Do not publish packages, releases, tags, or remote changes without explicit
  user authorization.
- Do not store credentials, tokens, customer data, or machine-specific paths.
- Record every adopted upstream baseline as an exact commit in
  `beacon/upstream.lock.json`; "latest" is a synchronization target, not a
  reproducible baseline.
- Review inherited workflows before enabling them. Upstream release automation
  must not publish Beacon artifacts.
- Run `node beacon/scripts/check-project.mjs`, the affected compile and test
  commands, and relevant formatting checks before committing Beacon changes.
