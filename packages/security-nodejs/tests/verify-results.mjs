import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const resultsDir = resolve(
  process.argv[2] ||
    process.env.BEACON_SECURITY_QA_RESULTS_DIR ||
    '/tmp/beacon_security-nodejs-qa-results'
);
const files = (await readdir(resultsDir)).filter(
  file => file.endsWith('.json') && file !== 'summary.json'
);
const results = [];
for (const file of files) {
  const result = JSON.parse(await readFile(join(resultsDir, file), 'utf8'));
  results.push({
    file,
    status: result.status,
    framework: result.framework,
    moduleSystem: result.moduleSystem,
  });
}
const counts = results.reduce((value, result) => {
  value[result.status] = (value[result.status] || 0) + 1;
  return value;
}, {});
const output = { schemaVersion: 1, resultsDir, counts, results };
process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
if ((counts.fail || 0) > 0) process.exitCode = 1;
else if ((counts.blocked || 0) > 0) process.exitCode = 2;
