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
const pkg = {
  name: 'beacon-nodejs-image',
  version,
  private: true,
  dependencies: Object.fromEntries(
    ['nodejs', 'profiler-nodejs', 'security-nodejs'].map(name => [
      `@beacon-observability/${name}`,
      version,
    ])
  ),
};
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
const published = json(join(output, 'assets/release-manifest.json'));
// Release 2.0.1 records npm verification using the newer artifact field names.
// Normalize distribution metadata while retaining the original release record.
const manifest = published.artifacts
  ? {
      version: published.version,
      tag: `v${published.version}`,
      source_commit: published.sourceCommit,
      items: published.artifacts.map(item => ({
        name: item.package,
        version: item.version,
        file: item.file,
        sha256: item.sha256,
        integrity: item.npmIntegrity,
        public_tarball: item.npmTarball,
        files: execFileSync(
          'tar',
          ['-tzf', join(output, 'assets', item.file)],
          {
            encoding: 'utf8',
          }
        )
          .trim()
          .split('\n')
          .filter(name => !name.endsWith('/')),
      })),
    }
  : published;
assert.equal(manifest.version, version);
assert.equal(manifest.tag, `v${version}`);
assert.equal(manifest.source_commit, commit);
assert.deepEqual(
  manifest.items.map(item => item.name).sort(),
  Object.keys(pkg.dependencies).sort()
);
for (const item of manifest.items) {
  assert.equal(pkg.dependencies[item.name], version);
  assert.equal(item.version, version);
  if (item.public_git_head !== undefined)
    assert.equal(item.public_git_head, commit);
  assert(names.includes(item.file));
  const bytes = readFileSync(join(output, 'assets', item.file));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), item.sha256);
  assert.equal(
    `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    item.integrity
  );
  const metadata = JSON.parse(
    execFileSync(
      'curl',
      [
        '--fail',
        '--silent',
        '--show-error',
        '--location',
        '--retry',
        '3',
        '--max-time',
        '60',
        `https://registry.npmjs.org/${encodeURIComponent(item.name)}/${version}`,
      ],
      { encoding: 'utf8' }
    )
  );
  // npm provenance does not always include gitHead; the immutable release
  // binds the source commit and the byte-identical public tarballs.
  if (metadata.gitHead !== undefined) assert.equal(metadata.gitHead, commit);
  assert.equal(metadata.name, item.name);
  assert.equal(metadata.version, version);
  assert.equal(metadata.dist.tarball, item.public_tarball);
  assert.equal(metadata.dist.integrity, item.integrity);
  console.log(`Verified ${item.name}@${version}: ${item.sha256}`);
}
writeFileSync(
  join(output, 'assets/distribution-manifest.json'),
  JSON.stringify(manifest, null, 2) + '\n'
);
writeFileSync(
  join(output, 'package.json'),
  JSON.stringify(pkg, null, 2) + '\n'
);
execFileSync(
  'npm',
  [
    'install',
    '--package-lock-only',
    '--ignore-scripts',
    '--omit=dev',
    '--no-audit',
    '--no-fund',
    '--workspaces=false',
    '--registry=https://registry.npmjs.org/',
  ],
  { cwd: output, stdio: 'inherit' }
);
const lock = json(join(output, 'package-lock.json'));
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
for (const item of manifest.items) {
  const entry = lock.packages[`node_modules/${item.name}`];
  assert.equal(entry.version, version);
  assert.equal(entry.integrity, item.integrity);
  assert.equal(entry.resolved, item.public_tarball);
}
copyFileSync(join(here, 'Dockerfile'), join(output, 'Dockerfile'));
writeFileSync(
  join(output, 'provenance.json'),
  JSON.stringify(
    {
      version,
      source_commit: commit,
      dependency_lock_sha256: createHash('sha256')
        .update(readFileSync(join(output, 'package-lock.json')))
        .digest('hex'),
      runtime: 'Node.js 24 / Debian bookworm glibc',
      npm_version: execFileSync('npm', ['--version'], {
        encoding: 'utf8',
      }).trim(),
      release: release.html_url,
    },
    null,
    2
  ) + '\n'
);
