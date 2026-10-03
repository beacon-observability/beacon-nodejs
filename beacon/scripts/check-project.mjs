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
  'beacon/security-migration.lock.json',
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
check(profiler.private !== true, 'Profiler must be publishable');
check(
  profiler.version === beaconVersion,
  'Profiler version must match beacon/version.properties'
);
check(
  profiler.publishConfig?.access === 'public',
  'Profiler package access must be public'
);
check(
  profiler.publishConfig?.registry === 'https://registry.npmjs.org/',
  'Profiler package must publish to the public npm registry'
);
check(
  profiler.repository?.url ===
    'git+https://github.com/beacon-observability/beacon-nodejs.git',
  'Profiler repository URL must point to Beacon Node.js'
);

const nodejs = readJson('packages/nodejs/package.json');
const security = readJson('packages/security-nodejs/package.json');
check(
  security.name === '@beacon-observability/security-nodejs',
  'Unexpected Beacon Security package name'
);
check(security.private !== true, 'Beacon Security must be publishable');
check(
  security.version === beaconVersion,
  'Beacon Security version must match beacon/version.properties'
);
check(
  security.publishConfig?.access === 'public',
  'Beacon Security package access must be public'
);
check(
  security.repository?.url ===
    'git+https://github.com/beacon-observability/beacon-nodejs.git',
  'Beacon Security repository URL must point to Beacon Node.js'
);
check(
  security.exports?.['./register'] === './src/register.mjs',
  'Beacon Security package must expose its preload entry point'
);

check(
  nodejs.name === '@beacon-observability/nodejs',
  'Unexpected Beacon Node.js package name'
);
check(nodejs.private !== true, 'Beacon Node.js package must be publishable');
check(
  nodejs.version === beaconVersion,
  'Beacon Node.js package version must match beacon/version.properties'
);
check(
  nodejs.publishConfig?.access === 'public',
  'Beacon Node.js package access must be public'
);
check(
  nodejs.publishConfig?.registry === 'https://registry.npmjs.org/',
  'Beacon Node.js package must publish to the public npm registry'
);
check(
  nodejs.repository?.url ===
    'git+https://github.com/beacon-observability/beacon-nodejs.git',
  'Beacon Node.js repository URL must point to Beacon Node.js'
);
check(
  nodejs.exports?.['./register']?.require === './build/src/register.js' &&
    nodejs.exports?.['./register']?.import === './register.mjs',
  'Beacon Node.js package must expose the zero-code register entry point'
);
check(
  nodejs.dependencies?.['@beacon-observability/profiler-nodejs'] ===
    `^${beaconVersion}`,
  'Beacon Node.js package must use the matching profiler version'
);
check(
  nodejs.dependencies?.['@beacon-observability/security-nodejs'] ===
    `^${beaconVersion}`,
  'Beacon Node.js package must use the matching Security version'
);

const securityMigration = readJson('beacon/security-migration.lock.json');
check(
  securityMigration.schemaVersion === 1,
  'Unsupported Security migration lock schema'
);
check(
  securityMigration.source?.repository ===
    'https://github.com/Guan' + 'ceCloud/SecurityContext.git' &&
    /^[0-9a-f]{40}$/.test(securityMigration.source?.commit ?? '') &&
    securityMigration.source?.subdirectory === 'nodejs',
  'Security migration source must be pinned to the original Node.js implementation'
);
check(
  securityMigration.contract?.repository ===
    'https://github.com/beacon-observability/beacon-security-spec' &&
    /^[0-9a-f]{40}$/.test(securityMigration.contract?.commit ?? '') &&
    securityMigration.contract?.schemaVersion === 1 &&
    securityMigration.contract?.fingerprintVersion === 1,
  'Beacon Security contract must be pinned to schema and fingerprint version 1'
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
  'Beacon profiler must skip inherited GitHub releases'
);
check(
  releaseConfig.packages?.['packages/nodejs']?.['skip-github-release'] === true,
  'Beacon Node.js package must skip inherited GitHub releases'
);
check(
  releaseConfig.packages?.['packages/security-nodejs']?.[
    'skip-github-release'
  ] === true,
  'Beacon Security must skip inherited GitHub releases'
);
const releaseManifest = readJson('.release-please-manifest.json');
check(
  releaseManifest['packages/profiler-nodejs'] === profiler.version,
  'Profiler release manifest version must match package version'
);
check(
  releaseManifest['packages/nodejs'] === nodejs.version,
  'Beacon Node.js release manifest version must match package version'
);
check(
  releaseManifest['packages/security-nodejs'] === security.version,
  'Beacon Security release manifest version must match package version'
);

const disallowedTerms = ['guan' + 'ce', 'cloud' + 'care', 'data' + 'kit'];
const grepArgs = ['grep', '-I', '-n', '-i'];
for (const term of disallowedTerms) grepArgs.push('-e', term);
grepArgs.push('--', '.', ':(exclude)beacon/security-migration.lock.json');
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
