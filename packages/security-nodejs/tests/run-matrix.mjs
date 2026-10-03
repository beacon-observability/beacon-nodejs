import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runCase } from './harness/runner.mjs';

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

const frameworks = option(
  '--frameworks',
  process.env.BEACON_SECURITY_QA_FRAMEWORKS || 'express4,express5,fastify5'
)
  .split(',')
  .filter(Boolean);
const moduleSystems = option(
  '--systems',
  process.env.BEACON_SECURITY_QA_MODULE_SYSTEMS || 'esm,cjs'
)
  .split(',')
  .filter(Boolean);
const resultsDir = resolve(
  option(
    '--results-dir',
    process.env.BEACON_SECURITY_QA_RESULTS_DIR ||
      '/tmp/beacon_security-nodejs-qa-results'
  )
);
const nodeLine = option(
  '--node-line',
  process.env.BEACON_SECURITY_QA_NODE_LINE || null
);
const timeoutMillis = Number(
  option('--timeout-ms', process.env.BEACON_SECURITY_QA_TIMEOUT_MS || '20000')
);

const results = [];
for (const framework of frameworks) {
  for (const moduleSystem of moduleSystems) {
    const result = await runCase({
      framework,
      moduleSystem,
      nodeLine,
      resultsDir,
      timeoutMillis,
    });
    results.push(result);
    process.stdout.write(
      `${JSON.stringify({ framework, moduleSystem, status: result.status, resultFile: result.resultFile, error: result.error?.message })}\n`
    );
  }
}

await mkdir(resultsDir, { recursive: true });
const summary = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  node: process.version,
  expectedNodeLine: nodeLine,
  requested: { frameworks, moduleSystems },
  counts: results.reduce((counts, result) => {
    counts[result.status] = (counts[result.status] || 0) + 1;
    return counts;
  }, {}),
  results: results.map(result => ({
    framework: result.framework,
    moduleSystem: result.moduleSystem,
    status: result.status,
    resultFile: result.resultFile,
  })),
};
await writeFile(
  resolve(resultsDir, 'summary.json'),
  `${JSON.stringify(summary, null, 2)}\n`,
  'utf8'
);

if ((summary.counts.fail || 0) > 0) process.exitCode = 1;
else if ((summary.counts.blocked || 0) > 0) process.exitCode = 2;
