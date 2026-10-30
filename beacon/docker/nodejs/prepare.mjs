import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const [version, target] = process.argv.slice(2);
assert.match(version || '', /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
assert(target, 'Usage: node prepare.mjs <X.Y.Z> <empty-staging-directory>');
const output = resolve(target);
mkdirSync(output, { recursive: true });
assert.equal(readdirSync(output).length, 0, 'Staging directory must be empty');
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const pkg = json(join(here, 'package.json'));
const lock = json(join(here, 'package-lock.json'));
assert.equal(
  pkg.version,
  version,
  'Commit the image dependency lock for this release first'
);
assert.equal(lock.version, version);
assert.deepEqual(lock.packages[''].dependencies, pkg.dependencies);
for (const [name, entry] of Object.entries(lock.packages)) {
  if (!name) continue;
  assert(
    entry.resolved?.startsWith('https://registry.npmjs.org/'),
    `Non-registry dependency: ${name}`
  );
  assert.match(entry.integrity || '', /^sha512-/);
  assert(
    !entry.link && !entry.dev,
    `Unexpected workspace/dev dependency: ${name}`
  );
}
const gh = args => execFileSync('gh', args, { encoding: 'utf8' });
const repo = 'beacon-observability/beacon-nodejs';
const release = JSON.parse(
  gh(['api', `repos/${repo}/releases/tags/v${version}`])
);
assert(!release.draft && !release.prerelease);
assert.equal(release.tag_name, `v${version}`);
const commit = gh([
  'api',
  `repos/${repo}/commits/v${version}`,
  '--jq',
  '.sha',
]).trim();
mkdirSync(join(output, 'assets'));
const names = [
  'release-manifest.json',
  ...['nodejs', 'profiler-nodejs', 'security-nodejs'].map(
    name => `beacon-observability-${name}-${version}.tgz`
  ),
];
gh([
  'release',
  'download',
  `v${version}`,
  '--repo',
  repo,
  '--dir',
  join(output, 'assets'),
  ...names.flatMap(name => ['--pattern', name]),
]);
const manifest = json(join(output, 'assets/release-manifest.json'));
assert.equal(manifest.version, version);
assert.equal(manifest.tag, `v${version}`);
assert.equal(manifest.source_commit, commit);
assert.equal(manifest.items.length, 3);
for (const item of manifest.items) {
  assert.equal(pkg.dependencies[item.name], version);
  assert.equal(item.version, version);
  assert.equal(item.public_git_head, commit);
  assert(names.includes(item.file));
  const bytes = readFileSync(join(output, 'assets', item.file));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), item.sha256);
  assert.equal(
    `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    item.integrity
  );
  const entry = lock.packages[`node_modules/${item.name}`];
  assert.equal(entry.version, version);
  assert.equal(entry.integrity, item.integrity);
  assert.equal(entry.resolved, item.public_tarball);
  const metadata = JSON.parse(
    execFileSync(
      'npm',
      [
        'view',
        `${item.name}@${version}`,
        'gitHead',
        'dist',
        '--json',
        '--registry=https://registry.npmjs.org/',
      ],
      { encoding: 'utf8' }
    )
  );
  assert.equal(metadata.gitHead, commit);
  assert.equal(metadata.dist.integrity, item.integrity);
  console.log(`Verified ${item.name}@${version}: ${item.sha256}`);
}
copyFileSync(join(here, 'package.json'), join(output, 'package.json'));
copyFileSync(
  join(here, 'package-lock.json'),
  join(output, 'package-lock.json')
);
writeFileSync(
  join(output, 'provenance.json'),
  JSON.stringify(
    {
      version,
      source_commit: commit,
      dependency_lock_sha256: createHash('sha256')
        .update(readFileSync(join(here, 'package-lock.json')))
        .digest('hex'),
      runtime: 'Node.js 24 / Debian bookworm glibc',
      release: release.html_url,
    },
    null,
    2
  ) + '\n'
);
