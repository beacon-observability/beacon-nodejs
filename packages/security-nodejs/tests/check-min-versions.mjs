function parseVersion(value) {
  const match = String(value).match(/v?(\d+)\.(\d+)\.(\d+)/);
  if (!match) throw new Error(`invalid_node_version:${value}`);
  return match.slice(1).map(Number);
}

function compare(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

const required = process.env.BEACON_SECURITY_QA_REQUIRED_VERSION;
if (!required) {
  process.stderr.write('BEACON_SECURITY_QA_REQUIRED_VERSION is required\n');
  process.exit(2);
}
const actual = parseVersion(process.version);
const minimum = parseVersion(required);
const ok = compare(actual, minimum) >= 0;
const result = {
  actual: process.version,
  minimum: `v${minimum.join('.')}`,
  ok,
};
process.stdout.write(`${JSON.stringify(result)}\n`);
if (!ok) process.exit(1);
