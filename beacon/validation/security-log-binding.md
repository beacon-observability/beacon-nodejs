# Security log binding adoption validation

Current source pins specification `d9d76e5a41d974d294bb596e06918bb954319bf6`
and output profile `beacon-security-log-body-v1`. This is source validation,
not release acceptance or a claim about every receiver.

The producer retains v2 fields at their existing paths, moves `observed_at` to
native event time and `occurrence_id` to log attribute `event_id`, and emits a
compact single-line JSON Body. The original inventory identity tuple and
fingerprint v1 remain unchanged. Byte budgets use the transmitted UTF-8 Body.

## Verification

- Node.js 24.16.0: all 136 Security tests passed (`node --test 'packages/security-nodejs/tests/*.test.mjs'`).
- Final binding/exporter checks passed again after formatting and removing an unused parameter (16 tests).
- `node beacon/scripts/check-project.mjs` and formatting checks passed.
- Real HTTP input and file sink produced a trace-correlated finding through the OTel SDK and Collector 0.135.0. The updated Collector verifier passed Body schema, native timestamp, event ID, source, invocation span and severity checks.
- Shared normative examples, nanosecond precision, invalid timestamps, retry identity, Unicode, sampling/truncation and multipart assembly are covered.

Dependencies were installed in a temporary standalone Security package directory;
the inherited workspace-wide compile and complete upstream matrix were not run.

## Shutdown regression follow-up

The review of PR #57 identified an active-request SIGTERM smoke assertion that
still decoded the historical SIEM envelope. The receiver now selects findings
using Body `event_name`, reads `event_id` from native log attributes, and checks
the native timestamp, compact Body, INFO severity, source and invocation trace/
span association. Body must not reintroduce time, occurrence ID or `message`.

- `node beacon/scripts/review-smoke.mjs` passed all six scenarios on Node.js
  22.22.3 and 24.16.0, including pending-request delivery before SDK shutdown.
- The smoke test compiled and installed the packed Beacon packages for each run.
- All 136 Security tests passed again on Node.js 24.16.0.
- Project metadata, Markdown, release-configuration and changed-file formatting
  checks passed. The repository formatter also identified a long metadata-check
  expression introduced by the new profile name; that formatting was corrected.
