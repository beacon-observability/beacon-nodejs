import { createHash, randomUUID } from 'node:crypto';
import { realpathSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainThread } from 'node:worker_threads';

export const VERSION = '1.1.0';
export const RULES = Object.freeze([
  'sql_injection',
  'command_execution',
  'command_injection',
  'ssrf',
  'http_request_input',
  'path_traversal',
]);
export const text = (key, fallback = '') =>
  process.env[key.toUpperCase().replace(/[.-]/g, '_')] ?? fallback;
export const flag = (key, fallback = true) =>
  text(key, String(fallback)).toLowerCase() === 'true';
export function limit(key, fallback) {
  const value = Number(text(key, String(fallback)));
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}
export const digest = value => createHash('sha256').update(value).digest('hex');
export const runtimeIdentity = () => ({
  language: 'javascript',
  implementation: 'nodejs',
  version: process.versions.node,
  os: process.platform,
  architecture: process.arch,
  details: {},
});
export function realPath(value) {
  try {
    return realpathSync.native(value);
  } catch {
    return path.resolve(value);
  }
}
const roots = key =>
  text(key)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(realPath);
export const includeRoots = roots('beacon.security.node.include');
const excludes = roots('beacon.security.node.exclude');
const ownRoot = realPath(fileURLToPath(new URL('.', import.meta.url)));
const within = (file, root) =>
  file === root || file.startsWith(root + path.sep);
export function included(file) {
  if (!file || file.startsWith('node:')) return false;
  try {
    if (file.startsWith('file:')) file = fileURLToPath(file);
  } catch {
    return false;
  }
  file = realPath(file);
  return (
    !within(file, ownRoot) &&
    !file.split(path.sep).includes('node_modules') &&
    includeRoots.some(root => within(file, root)) &&
    !excludes.some(root => within(file, root))
  );
}
const runtimeSupported = (() => {
  const [major, minor, patch] = process.versions.node.split('.').map(Number);
  return (
    isMainThread &&
    ((major === 22 && (minor > 22 || (minor === 22 && patch >= 3))) ||
      (major === 24 && (minor > 11 || (minor === 11 && patch >= 1))))
  );
})();
export function supportedRuntime() {
  return runtimeSupported;
}
let loaderCompatible = true;
let instrumentationActive = true;
export function instrumentationEnabled(enabled) {
  instrumentationActive = enabled;
}
export const instrumentationIsEnabled = () => instrumentationActive;
export function loaderCompatibility(compatible) {
  loaderCompatible = compatible;
}
export function collectionConfigured() {
  return (
    flag('beacon.security.enabled', false) &&
    includeRoots.length > 0 &&
    supportedRuntime() &&
    loaderCompatible &&
    instrumentationActive
  );
}
let cachedIdentity;
export function identity() {
  if (cachedIdentity) return cachedIdentity;
  const service = {};
  const accepted = new Set([
    'service.name',
    'service.version',
    'service.namespace',
    'service.instance.id',
    'deployment.environment.name',
  ]);
  for (const entry of text('otel.resource.attributes').split(',')) {
    const split = entry.indexOf('=');
    if (split > 0 && accepted.has(entry.slice(0, split)))
      service[entry.slice(0, split)] = entry.slice(split + 1).slice(0, 512);
  }
  if (text('otel.service.name'))
    service['service.name'] = text('otel.service.name').slice(0, 512);
  cachedIdentity = {
    application_id: (
      'app-' +
      digest(
        (service['service.namespace'] || '') +
          '|' +
          (service['service.name'] || 'unknown_service:node')
      )
    ).slice(0, 1024),
    instance_id: randomUUID(),
    service,
    code: {
      repository: text('beacon.security.code.repository').slice(0, 1024),
      commit: text('beacon.security.code.commit').slice(0, 1024),
      build_id: text('beacon.security.code.build-id').slice(0, 1024),
      service_version: service['service.version'] || '',
    },
    runtime: runtimeIdentity(),
    identity_status: service['service.name'] ? 'configured' : 'fallback',
  };
  return cachedIdentity;
}
export function profile(adapters = []) {
  const budgets = Object.fromEntries(
    [
      'max.objects',
      'max.nodes',
      'max.marks-per-object',
      'max.findings',
      'max.tracked.bytes',
      'max.process.tracked.bytes',
      'runs.max.bytes',
      'max.active.requests',
      'requests-per-second',
      'evidence.max.bytes',
      'export.queue.size',
      'export.sbom.queue.size',
    ].map(k => [k, text('beacon.security.' + k)])
  );
  return digest(
    JSON.stringify({
      version: VERSION,
      runtime: runtimeIdentity(),
      adapters: [...adapters].sort(),
      dependencies: dependencyVersions(),
      include: includeRoots,
      exclude: excludes,
      rules: Object.fromEntries(
        RULES.map(r => [r, flag('beacon.security.rules.' + r + '.enabled')])
      ),
      budgets,
    })
  );
}
let versions;
function dependencyVersions() {
  if (versions) return versions;
  versions = {};
  const require = createRequire(
    path.resolve(process.argv[1] || path.join(process.cwd(), 'package.json'))
  );
  for (const name of [
    'express',
    'express4',
    'fastify',
    'pg',
    'mysql2',
    'undici',
    '@opentelemetry/api',
    '@opentelemetry/instrumentation',
    '@opentelemetry/sdk-node',
    'import-in-the-middle',
  ]) {
    versions[name] = 'not_resolved';
    try {
      let directory = path.dirname(require.resolve(name));
      for (let depth = 0; depth < 12; depth++) {
        try {
          const pkg = JSON.parse(
            readFileSync(path.join(directory, 'package.json'), 'utf8')
          );
          if (pkg.name && pkg.version) {
            versions[name] = pkg.name + '@' + pkg.version;
            break;
          }
        } catch {
          /* A module can start below its package root. */
        }
        const parent = path.dirname(directory);
        if (parent === directory) break;
        directory = parent;
      }
    } catch {
      /* An adapter may never be installed or loaded by this application. */
    }
  }
  return versions;
}
