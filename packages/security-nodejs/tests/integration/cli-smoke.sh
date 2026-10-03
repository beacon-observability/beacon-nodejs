#!/usr/bin/env bash
set -euo pipefail

# This wrapper talks to the existing CLI and a live output directory. It does
# not synthesize health/control files: missing or stale agent state is a
# blocked result that the caller must retain.
nodejs_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output_dir=${BEACON_SECURITY_QA_CONTROL_DIR:?BEACON_SECURITY_QA_CONTROL_DIR must point at a live Node output directory}
python_bin=${PYTHON_BIN:-python3}
ctl=("$python_bin" "$nodejs_root/tests/fixtures/securityctl.py" --dir "$output_dir")
record_dir=${BEACON_SECURITY_QA_CLI_RESULTS_DIR:-/tmp/beacon_security-nodejs-cli-results}
mkdir -p "$record_dir"
failed_commands=0

run_and_record() {
  local name=$1
  shift
  set +e
  "$@" >"$record_dir/$name.json" 2>"$record_dir/$name.stderr"
  local code=$?
  set -e
  printf '%s\n' "{\"command\":\"$name\",\"exit_code\":$code}" >"$record_dir/$name.status.json"
  if [[ "$code" -ne 0 ]]; then failed_commands=$((failed_commands + 1)); fi
  return 0
}

run_and_record status "${ctl[@]}" status
run_and_record pause "${ctl[@]}" pause
run_and_record resume "${ctl[@]}" resume
run_and_record run-start "${ctl[@]}" run-start \
  --case "${BEACON_SECURITY_QA_CASE:-node-qa}" \
  --rule "${BEACON_SECURITY_QA_RULE:-sql_injection}" \
  --suite "${BEACON_SECURITY_QA_SUITE:-node-matrix}" \
  --fixture "${BEACON_SECURITY_QA_FIXTURE:-matrix}" \
  --expected-requests "${BEACON_SECURITY_QA_EXPECTED_REQUESTS:-1}"
run_and_record run-stop "${ctl[@]}" run-stop --output "$record_dir/run-stop.json"

if [[ -n "${BEACON_SECURITY_QA_BASELINE:-}" && -n "${BEACON_SECURITY_QA_CANDIDATE:-}" ]]; then
  set +e
  "${ctl[@]}" verify --baseline "$BEACON_SECURITY_QA_BASELINE" --candidate "$BEACON_SECURITY_QA_CANDIDATE" --output "$record_dir/verify.json" >"$record_dir/verify.stdout" 2>"$record_dir/verify.stderr"
  verify_code=$?
  set -e
  printf '%s\n' "{\"command\":\"verify\",\"exit_code\":$verify_code}" >"$record_dir/verify.status.json"
  if [[ "${BEACON_SECURITY_QA_EXPECT_INCONCLUSIVE:-false}" == true && "$verify_code" -ne 3 ]]; then
    echo "expected verify to return 3 for inconclusive, got $verify_code" >&2
    exit 1
  fi
  if [[ "$verify_code" -ne 0 && ! ("${BEACON_SECURITY_QA_EXPECT_INCONCLUSIVE:-false}" == true && "$verify_code" -eq 3) ]]; then
    failed_commands=$((failed_commands + 1))
  fi
fi

if [[ "$failed_commands" -gt 0 ]]; then
  echo "cli smoke blocked or failed commands=$failed_commands; inspect $record_dir/*.status.json" >&2
  exit 2
fi
