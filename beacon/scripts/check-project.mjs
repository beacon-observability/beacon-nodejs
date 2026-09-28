import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const errors = [];

function readText(relativePath) {
  return readFileSync(path.join(root, relativePath), 'utf8');
}

function readJson(relativePath) {
  return JSON.parse(readText(relativePath));
}

function check(condition, message) {
  if (!condition) errors.push(message);
}

const requiredFiles = [
  'beacon/README.md',
  'beacon/CHANGELOG.md',
  'beacon/CI.md',
  'beacon/CONTRIBUTORS.md',
  'beacon/RELEASING.md',
  'beacon/UPSTREAM.md',
  'beacon/upstream.lock.json',
  'beacon/version.properties',
  '.github/workflows/beacon-ci.yml',
];

for (const relativePath of requiredFiles) {
  try {
    readText(relativePath);
  } catch {
    errors.push(`Missing required file: ${relativePath}`);
  }
}

const versionMatch = readText('beacon/version.properties').match(
  /^version=([^\s]+)$/m
);
check(versionMatch !== null, 'Missing Beacon product version');
const beaconVersion = versionMatch?.[1] ?? '';
check(
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:dev|rc\.(0|[1-9]\d*)|[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.test(
    beaconVersion
  ),
  `Invalid Beacon product version: ${beaconVersion}`
);

const profiler = readJson('packages/profiler-nodejs/package.json');
check(
  profiler.name === '@beacon-observability/profiler-nodejs',
  'Unexpected profiler package name'
);
check(profiler.private === true, 'Profiler must remain private before release');
check(
  profiler.version === beaconVersion,
  'Profiler version must match beacon/version.properties'
);
check(
  profiler.repository?.url ===
    'git+https://github.com/beacon-observability/beacon-nodejs.git',
  'Profiler repository URL must point to Beacon Node.js'
);

const traceDemo = readJson('examples/trace-profile-demo/package.json');
check(
  traceDemo.dependencies?.['@beacon-observability/profiler-nodejs'] ===
    'file:../../packages/profiler-nodejs',
  'Trace/profile demo must use the local profiler workspace'
);

const source = readJson('beacon/upstream.lock.json');
const officialRepository =
  'https://github.com/open-telemetry/opentelemetry-js-contrib.git';
check(source.schemaVersion === 1, 'Unsupported upstream lock schema');
for (const sectionName of ['import', 'upstream']) {
  const section = source[sectionName];
  check(section !== undefined, `Missing ${sectionName} source record`);
  check(
    section?.repository === officialRepository,
    `${sectionName} repository must be the official OpenTelemetry repository`
  );
  check(section?.branch === 'main', `${sectionName} branch must be main`);
  check(
    /^[0-9a-f]{40}$/.test(section?.commit ?? ''),
    `${sectionName} commit must be a full lowercase SHA`
  );
}

if (/^[0-9a-f]{40}$/.test(source.upstream?.commit ?? '')) {
  const ancestor = spawnSync(
    'git',
    ['merge-base', '--is-ancestor', source.upstream.commit, 'HEAD'],
    { cwd: root }
  );
  check(
    ancestor.status === 0,
    'Recorded upstream commit must be an ancestor of HEAD'
  );
}

const releaseConfig = readJson('release-please-config.json');
check(
  releaseConfig.packages?.['packages/profiler-nodejs']?.[
    'skip-github-release'
  ] === true,
  'Private profiler must skip GitHub releases'
);
const releaseManifest = readJson('.release-please-manifest.json');
check(
  releaseManifest['packages/profiler-nodejs'] === undefined,
  'Private profiler must not appear in the release manifest'
);

const disallowedTerms = ['guan' + 'ce', 'cloud' + 'care', 'data' + 'kit'];
const grepArgs = ['grep', '-I', '-n', '-i'];
for (const term of disallowedTerms) grepArgs.push('-e', term);
grepArgs.push('--', '.');
const disallowedResult = spawnSync('git', grepArgs, {
  cwd: root,
  encoding: 'utf8',
});
if (disallowedResult.status === 0) {
  errors.push(`Disallowed legacy wording found:\n${disallowedResult.stdout}`);
} else if (disallowedResult.status !== 1) {
  errors.push(`Unable to scan tracked files: ${disallowedResult.stderr}`);
}

const markdownFiles = execFileSync('git', ['ls-files', '-z', '--', '*.md'], {
  cwd: root,
  encoding: 'utf8',
})
  .split('\0')
  .filter(Boolean);
for (const relativePath of markdownFiles) {
  if (/\p{Script=Han}/u.test(readText(relativePath))) {
    errors.push(`Beacon documentation must be English: ${relativePath}`);
  }
}

if (errors.length > 0) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(
  `Beacon Node.js ${beaconVersion}: metadata and upstream provenance are valid`
);
