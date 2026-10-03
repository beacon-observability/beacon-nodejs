import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parentPort, workerData } from 'node:worker_threads';
import { dependencySnapshot } from './snapshot.mjs';

const data = workerData || {};
const identity = data.identity || {};
const settings = {
  maxComponents: positive(data.settings?.maxComponents, 10000),
  maxEntries: positive(data.settings?.maxEntries, 100000),
  maxArchiveBytes: positive(data.settings?.maxArchiveBytes, 64 * 1024 * 1024),
  maxScanBytes: positive(data.settings?.maxScanBytes, 512 * 1024 * 1024),
  cacheSeconds: positive(data.settings?.cacheSeconds, 300),
  refreshSeconds: positive(data.settings?.refreshSeconds, 5),
  maxQueue: positive(data.settings?.maxQueue, 4096),
};

const sbomId = bounded(data.sbomId, 256) || `urn:uuid:${crypto.randomUUID()}`;
const output = path.resolve(
  bounded(data.output, 4096) ||
    path.join(process.cwd(), 'beacon-security-output', 'application.cdx.json')
);
const historyPath = path.join(path.dirname(output), 'sbom-history.json');
const localOutputEnabled = data.localOutputEnabled === true;
const include = Array.isArray(data.include)
  ? data.include
      .slice(0, 256)
      .map(item => bounded(item, 4096))
      .filter(Boolean)
  : [process.cwd()];
const buildFile = bounded(data.buildFile, 4096);
const toolVersion = bounded(data.version, 128);
const applicationId =
  bounded(identity.application_id, 1024) ||
  `app-${sha256('unknown-node-application')}`;

const state = {
  observations: new Map(),
  pendingTimer: null,
  refreshing: false,
  refreshAgain: false,
  closing: false,
  closeAfterRefresh: false,
  lastSuccessAt: '',
  lastFailureAt: '',
  lastErrorType: '',
  published: {
    revision: 0,
    releaseId: 'unresolved',
    contentSha256: '',
    componentCount: 0,
    reasons: new Set(['runtime_dependency_graph_incomplete']),
    quality: emptyQuality(),
  },
  previousDigests: new Map(),
  history: new Map(),
  historyLoaded: false,
  baseCache: null,
  baseCacheKey: '',
  baseCacheAt: 0,
};

function positive(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : fallback;
}

function bounded(value, maximum = 2048) {
  if (value === undefined || value === null) return '';
  try {
    return String(value).slice(0, maximum);
  } catch {
    return '';
  }
}

function sha256(value) {
  return crypto
    .createHash('sha256')
    .update(String(value), 'utf8')
    .digest('hex');
}

function sha256Bytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== 'object') return value;
  const result = {};
  for (const key of Object.keys(value).sort())
    result[key] = stableValue(value[key]);
  return result;
}

function stableJson(value) {
  return JSON.stringify(stableValue(value));
}

function nowIso() {
  return new Date().toISOString();
}

function emptyQuality() {
  return {
    components: 0,
    with_purl: 0,
    with_version: 0,
    with_hash: 0,
    with_license: 0,
    loaded_components: 0,
  };
}

function recordEntries(map) {
  return [...map.values()].sort((left, right) =>
    left.ref.localeCompare(right.ref)
  );
}

function markReason(reasons, value) {
  const reason = bounded(value, 256);
  if (reason && reasons.size < 256) reasons.add(reason);
}

function addBytes(context, size, reasons) {
  const amount = Number(size);
  if (!Number.isFinite(amount) || amount < 0) return false;
  if (context.scanBytes + amount > settings.maxScanBytes) {
    markReason(reasons, 'scan_byte_limit');
    return false;
  }
  context.scanBytes += amount;
  return true;
}

function addEntry(context, reasons) {
  context.entries += 1;
  if (context.entries > settings.maxEntries) {
    markReason(reasons, 'entry_limit');
    return false;
  }
  return true;
}

function safeStat(filename) {
  try {
    return fs.statSync(filename);
  } catch {
    return null;
  }
}

function realPath(filename) {
  try {
    return fs.realpathSync.native(filename);
  } catch {
    return '';
  }
}

function within(filename, root) {
  const file = path.resolve(filename);
  const base = path.resolve(root);
  return file === base || file.startsWith(`${base}${path.sep}`);
}

function packageNameFromKey(key) {
  const value = bounded(key, 4096).replaceAll('\\', '/');
  const marker = '/node_modules/';
  const index = value.lastIndexOf(marker);
  if (index < 0) return '';
  return value.slice(index + marker.length).split('/node_modules/')[0];
}

function validNpmName(value) {
  const name = bounded(value, 512).trim();
  if (!name || name.length > 214 || /[\\\s]/.test(name) || name.includes('..'))
    return false;
  if (name.startsWith('@')) return /^@[a-z0-9._~-]+\/[a-z0-9._~-]+$/.test(name);
  return /^[a-z0-9._~-]+$/.test(name);
}

function npmPurl(name, version) {
  const packageName = bounded(name, 512).trim();
  const packageVersion = bounded(version, 256).trim();
  if (
    !validNpmName(packageName) ||
    !packageVersion ||
    /[\s]/.test(packageVersion)
  )
    return '';
  return `pkg:npm/${encodeURIComponent(packageName)}@${encodeURIComponent(packageVersion)}`;
}

function packageJsonLicense(value) {
  if (typeof value === 'string') {
    const name = bounded(value, 512).trim();
    return name ? [{ license: { name } }] : [];
  }
  if (value && typeof value === 'object') {
    const name = bounded(value.id || value.name, 512).trim();
    return name ? [{ license: { name } }] : [];
  }
  return [];
}

function declaredLicenses(value) {
  if (!Array.isArray(value)) return [];
  const result = [];
  for (const item of value.slice(0, 16)) {
    if (!item || typeof item !== 'object') continue;
    const license = item.license;
    if (license && typeof license === 'object') {
      const name = bounded(license.name || license.id, 512).trim();
      if (name) result.push({ license: { name } });
    } else if (item.expression) {
      result.push({ expression: bounded(item.expression, 512) });
    }
  }
  return result;
}

function property(name, value) {
  return { name: bounded(name, 256), value: bounded(value, 2048) };
}

function getDependencies(value) {
  const result = {};
  for (const field of [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
  ]) {
    const item = value && typeof value[field] === 'object' ? value[field] : {};
    for (const [name, version] of Object.entries(item).slice(
      0,
      settings.maxEntries
    )) {
      if (!(name in result)) result[bounded(name, 512)] = bounded(version, 256);
    }
  }
  return result;
}

function parseObserved(raw) {
  const value = bounded(raw, 4096).trim();
  if (!value) return { reason: 'empty_observation' };
  let url;
  try {
    url = new URL(value);
  } catch {
    return { reason: 'invalid_file_url' };
  }
  if (url.protocol !== 'file:')
    return {
      url: url.href,
      query: url.search,
      reason: 'unsupported_url_scheme',
    };
  try {
    const filename = path.resolve(fileURLToPath(url));
    return { path: filename, url: url.href, query: url.search };
  } catch {
    return { url: url.href, query: url.search, reason: 'invalid_file_url' };
  }
}

function readJson(filename, context, reasons, reasonPrefix) {
  const stat = safeStat(filename);
  if (!stat || !stat.isFile()) {
    markReason(reasons, `${reasonPrefix}_unreadable`);
    return null;
  }
  if (stat.size > settings.maxArchiveBytes) {
    markReason(reasons, `${reasonPrefix}_byte_limit`);
    return null;
  }
  if (!addBytes(context, stat.size, reasons)) return null;
  let raw;
  try {
    raw = fs.readFileSync(filename);
  } catch {
    markReason(reasons, `${reasonPrefix}_unreadable`);
    return null;
  }
  try {
    const value = JSON.parse(raw.toString('utf8'));
    if (!boundedJson(value, 0, { count: 0 })) {
      markReason(reasons, `${reasonPrefix}_entry_limit`);
      return null;
    }
    return value && typeof value === 'object' ? value : null;
  } catch {
    markReason(reasons, `invalid_${reasonPrefix}`);
    return null;
  }
}

function boundedJson(value, depth, counter) {
  if (depth > 64 || counter.count >= settings.maxEntries) return false;
  counter.count += 1;
  if (Array.isArray(value)) {
    if (value.length > settings.maxEntries) return false;
    for (const item of value)
      if (!boundedJson(item, depth + 1, counter)) return false;
    return true;
  }
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (bounded(key, 4096).length !== key.length) return false;
      if (!boundedJson(item, depth + 1, counter)) return false;
    }
  }
  return true;
}

function normalizeResolved(root, resolved) {
  const value = bounded(resolved, 4096).trim();
  if (!value.startsWith('file:')) return '';
  try {
    return path.resolve(fileURLToPath(new URL(value)));
  } catch {
    return path.resolve(root, value.slice('file:'.length));
  }
}

function hashLocalFile(filename, context, reasons) {
  const stat = safeStat(filename);
  if (!stat || !stat.isFile()) return null;
  if (
    stat.size > settings.maxArchiveBytes ||
    !addBytes(context, stat.size, reasons)
  ) {
    markReason(reasons, 'archive_byte_limit');
    return null;
  }
  let bytes;
  try {
    bytes = fs.readFileSync(filename);
  } catch {
    markReason(reasons, 'unreadable_artifact');
    return null;
  }
  const sha512 = crypto.createHash('sha512').update(bytes).digest('base64');
  return { sha256: sha256Bytes(bytes), sha512 };
}

function componentRef(purl, name, version, scope, artifactHash = '') {
  if (artifactHash) return `urn:beacon:security:component:${artifactHash}`;
  return `urn:beacon:security:component:${sha256([purl, name, version, scope].join('|'))}`;
}

function pathLabel(filename) {
  const value = bounded(filename, 4096).replaceAll('\\', '/');
  const index = value.lastIndexOf('/');
  return bounded(index >= 0 ? value.slice(index + 1) : value, 2048);
}

function createComponent({
  name,
  version,
  purl,
  root,
  source,
  installed,
  declared,
  lockEntry,
  licenses,
  group,
  artifact,
}) {
  const artifactHash = artifact?.sha256 || '';
  const scope = realPath(root) || path.resolve(root);
  const ref = componentRef(purl, name, version, scope, artifactHash);
  const integrity = bounded(lockEntry?.integrity, 2048);
  const component = {
    ref,
    name: bounded(name, 512) || 'unknown-npm-component',
    version: bounded(version, 256),
    purl: bounded(purl, 2048),
    group: bounded(group, 512),
    source: bounded(source, 256) || 'package.json',
    installed: Boolean(installed),
    declared: Boolean(declared),
    loaded: false,
    packageRoots: new Set([path.resolve(root), ...(scope ? [scope] : [])]),
    dependencies: new Set(),
    dependencyNames: [],
    licenses: licenses?.slice(0, 16) || [],
    integrity,
    artifactHash,
    artifactIntegrity: artifact?.sha512 || '',
    integrityStatus: artifact?.verified
      ? 'verified'
      : integrity
        ? 'declared'
        : 'missing',
    authenticityStatus: artifact?.verified
      ? 'verified-local-integrity'
      : 'unverified',
    hashStatus: artifactHash ? 'observed-artifact' : 'unavailable',
    externalHashDeclared: false,
  };
  if (artifact && integrity && !artifact.verified) {
    const expected = integrity.match(/^sha512-(.+)$/)?.[1];
    if (expected && expected !== artifact.sha512) {
      component.integrityStatus = 'mismatch';
      component.authenticityStatus = 'failed';
    }
  }
  return component;
}

function mergeComponent(existing, incoming) {
  if (!existing) return incoming;
  for (const item of incoming.packageRoots) existing.packageRoots.add(item);
  existing.installed ||= incoming.installed;
  existing.declared ||= incoming.declared;
  existing.loaded ||= incoming.loaded;
  if (!existing.version && incoming.version)
    existing.version = incoming.version;
  if (!existing.purl && incoming.purl) existing.purl = incoming.purl;
  if (!existing.integrity && incoming.integrity)
    existing.integrity = incoming.integrity;
  if (
    existing.integrityStatus === 'missing' &&
    incoming.integrityStatus !== 'missing'
  )
    existing.integrityStatus = incoming.integrityStatus;
  if (
    existing.authenticityStatus === 'unverified' &&
    incoming.authenticityStatus !== 'unverified'
  )
    existing.authenticityStatus = incoming.authenticityStatus;
  if (!existing.artifactHash && incoming.artifactHash) {
    existing.artifactHash = incoming.artifactHash;
    existing.hashStatus = incoming.hashStatus;
  }
  for (const license of incoming.licenses) {
    if (existing.licenses.length >= 16) break;
    if (stableJson(existing.licenses).indexOf(stableJson(license)) < 0)
      existing.licenses.push(license);
  }
  return existing;
}

function appPackageRoot(root, context, reasons) {
  let current = path.resolve(root);
  const initial = safeStat(current);
  if (initial?.isFile()) current = path.dirname(current);
  for (let index = 0; index < 32; index += 1) {
    if (!addEntry(context, reasons)) return '';
    const packageFile = path.join(current, 'package.json');
    const stat = safeStat(packageFile);
    if (stat?.isFile()) return realPath(current) || current;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  markReason(reasons, 'application_package_json_unreadable');
  return '';
}

function findPackageJson(packageRoot, context, reasons, cache = new Map()) {
  const key = path.resolve(packageRoot);
  if (cache.has(key)) return cache.get(key);
  const value = readJson(
    path.join(key, 'package.json'),
    context,
    reasons,
    'package_json'
  );
  cache.set(key, value);
  return value;
}

function addPackage({
  packageRoot,
  root,
  value,
  lockEntry,
  source,
  records,
  pathRefs,
  pending,
  context,
  reasons,
}) {
  if (!addEntry(context, reasons)) return null;
  const resolvedRoot = realPath(packageRoot) || path.resolve(packageRoot);
  const packageValue = value && typeof value === 'object' ? value : {};
  const name = bounded(
    packageValue.name ||
      lockEntry?.name ||
      packageNameFromKey(path.relative(root, packageRoot)),
    512
  ).trim();
  const version = bounded(
    packageValue.version || lockEntry?.version,
    256
  ).trim();
  const purl = npmPurl(name, version);
  if (!purl) markReason(reasons, 'incomplete_npm_identity');
  const artifactPath = normalizeResolved(root, lockEntry?.resolved);
  const artifact = artifactPath
    ? hashLocalFile(artifactPath, context, reasons)
    : null;
  const component = createComponent({
    name,
    version,
    purl,
    root: resolvedRoot,
    source,
    installed: Boolean(value && Object.keys(value).length),
    declared: Boolean(lockEntry),
    lockEntry,
    licenses: packageJsonLicense(packageValue.license),
    artifact,
  });
  const existing = records.get(component.ref);
  // A package-lock entry may expose a local file: tarball digest while the
  // installed-tree walk sees only package.json. Reuse one path/PURL identity.
  let samePackage = existing;
  if (!samePackage && purl) {
    for (const candidate of records.values()) {
      if (
        candidate.purl === purl &&
        [...candidate.packageRoots].some(
          item => item === resolvedRoot || item === path.resolve(packageRoot)
        )
      ) {
        samePackage = candidate;
        break;
      }
    }
  }
  const selected = mergeComponent(samePackage, component);
  if (samePackage && samePackage.ref !== component.ref)
    records.delete(component.ref);
  if (!samePackage && records.size >= Math.max(0, settings.maxComponents - 1)) {
    markReason(reasons, 'component_count_limit');
    return null;
  }
  records.set(selected.ref, selected);
  pathRefs.set(path.resolve(packageRoot), selected.ref);
  pathRefs.set(resolvedRoot, selected.ref);
  if (records.size > settings.maxComponents - 1)
    markReason(reasons, 'component_count_limit');
  const dependencies = getDependencies(lockEntry || {});
  pending.push({
    ref: selected.ref,
    packageRoot: path.resolve(packageRoot),
    dependencies,
  });
  return selected;
}

function packageRootCandidates(root, name, packagePathRefs) {
  const result = [];
  let current = path.resolve(packagePathRefs);
  while (within(current, root)) {
    result.push(path.join(current, 'node_modules', name));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return result;
}

function lookupPackageRef(root, fromRoot, dependencyName, pathRefs) {
  for (const candidate of packageRootCandidates(
    root,
    dependencyName,
    fromRoot
  )) {
    const direct = pathRefs.get(path.resolve(candidate));
    if (direct) return direct;
    const resolved = realPath(candidate);
    if (resolved && pathRefs.has(resolved)) return pathRefs.get(resolved);
  }
  return '';
}

function addDependency(dependencies, from, to, reasons) {
  if (!from || !to || from === to) return;
  let targets = dependencies.get(from);
  if (!targets) {
    targets = new Set();
    dependencies.set(from, targets);
  }
  if (targets.size < settings.maxEntries) targets.add(to);
  else markReason(reasons, 'dependency_entry_limit');
}

function scanPackageDirectory(
  packageRoot,
  root,
  records,
  pathRefs,
  pending,
  context,
  reasons,
  packageCache,
  visited
) {
  if (!addEntry(context, reasons)) return;
  const lexical = path.resolve(packageRoot);
  const real = realPath(lexical) || lexical;
  if (visited.has(real)) return;
  visited.add(real);
  const packageValue = findPackageJson(lexical, context, reasons, packageCache);
  if (packageValue)
    addPackage({
      packageRoot: lexical,
      root,
      value: packageValue,
      source: 'package.json',
      records,
      pathRefs,
      pending,
      context,
      reasons,
    });
  const nested = path.join(lexical, 'node_modules');
  const stat = safeStat(nested);
  if (!stat?.isDirectory()) return;
  scanNodeModules(
    nested,
    root,
    records,
    pathRefs,
    pending,
    context,
    reasons,
    packageCache,
    visited
  );
}

function scanNodeModules(
  nodeModules,
  root,
  records,
  pathRefs,
  pending,
  context,
  reasons,
  packageCache,
  visited
) {
  if (!addEntry(context, reasons)) return;
  let entries;
  try {
    entries = fs.readdirSync(nodeModules, { withFileTypes: true });
  } catch {
    markReason(reasons, 'node_modules_unreadable');
    return;
  }
  for (const entry of entries.slice(0, settings.maxEntries)) {
    if (!addEntry(context, reasons)) return;
    if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
    const first = path.join(nodeModules, entry.name);
    if (entry.name.startsWith('@')) {
      let scoped;
      try {
        scoped = fs.readdirSync(first, { withFileTypes: true });
      } catch {
        markReason(reasons, 'node_modules_unreadable');
        continue;
      }
      for (const child of scoped.slice(0, settings.maxEntries)) {
        if (!child.isDirectory() && !child.isSymbolicLink()) continue;
        scanPackageDirectory(
          path.join(first, child.name),
          root,
          records,
          pathRefs,
          pending,
          context,
          reasons,
          packageCache,
          visited
        );
      }
    } else {
      scanPackageDirectory(
        first,
        root,
        records,
        pathRefs,
        pending,
        context,
        reasons,
        packageCache,
        visited
      );
    }
  }
  if (entries.length > settings.maxEntries) markReason(reasons, 'entry_limit');
}

function findLockPath(root) {
  const candidate = path.join(root, 'package-lock.json');
  return safeStat(candidate)?.isFile() ? candidate : '';
}

function discoverRoot(root, context, reasons) {
  const packageCache = new Map();
  const records = new Map();
  const pathRefs = new Map();
  const pending = [];
  const dependencies = new Map();
  const appRoots = [];
  const visited = new Set();
  const appRoot = appPackageRoot(root, context, reasons);
  if (!appRoot) return { records, pathRefs, dependencies, appRoots };
  appRoots.push(appRoot);
  const packageValue = findPackageJson(appRoot, context, reasons, packageCache);
  const lockPath = findLockPath(appRoot);
  let lock = null;
  if (lockPath) lock = readJson(lockPath, context, reasons, 'package_lock');
  if (lock && lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) {
    markReason(reasons, 'unsupported_package_lock_version');
    lock = null;
  }
  const pnpm = safeStat(path.join(appRoot, 'pnpm-lock.yaml'))?.isFile();
  const pnp = ['.pnp.cjs', '.pnp.js', '.pnp.data.json'].some(name =>
    safeStat(path.join(appRoot, name))?.isFile()
  );
  if (pnpm) {
    markReason(reasons, 'pnpm_lock_unsupported');
    markReason(reasons, 'runtime_dependency_graph_incomplete');
  }
  if (pnp) {
    markReason(reasons, 'yarn_pnp_unsupported');
    markReason(reasons, 'runtime_dependency_graph_incomplete');
  }
  const packageEntries =
    lock?.packages && typeof lock.packages === 'object' ? lock.packages : {};
  if (lock && Object.keys(packageEntries).length) {
    for (const [key, entry] of Object.entries(packageEntries).slice(
      0,
      settings.maxEntries
    )) {
      if (!addEntry(context, reasons)) break;
      if (
        !key ||
        key === '' ||
        !key.includes('node_modules/') ||
        !entry ||
        typeof entry !== 'object'
      )
        continue;
      const packageRoot = path.resolve(appRoot, key);
      if (!within(packageRoot, appRoot)) {
        markReason(reasons, 'package_lock_path_escape');
        continue;
      }
      const packageJson = findPackageJson(
        packageRoot,
        context,
        reasons,
        packageCache
      );
      addPackage({
        packageRoot,
        root: appRoot,
        value: packageJson,
        lockEntry: entry,
        source: 'package-lock',
        records,
        pathRefs,
        pending,
        context,
        reasons,
      });
    }
    const rootEntry =
      packageEntries[''] && typeof packageEntries[''] === 'object'
        ? packageEntries['']
        : packageValue || {};
    pending.push({
      ref: applicationId,
      packageRoot: appRoot,
      dependencies: getDependencies(rootEntry),
    });
  } else {
    markReason(reasons, 'runtime_dependency_graph_incomplete');
  }
  const modulesPath = path.join(appRoot, 'node_modules');
  if (safeStat(modulesPath)?.isDirectory())
    scanNodeModules(
      modulesPath,
      appRoot,
      records,
      pathRefs,
      pending,
      context,
      reasons,
      packageCache,
      visited
    );
  if (!records.size && lock) markReason(reasons, 'no_installed_npm_components');
  for (const item of pending) {
    for (const dependencyName of Object.keys(item.dependencies || {}).slice(
      0,
      settings.maxEntries
    )) {
      const target = lookupPackageRef(
        appRoot,
        item.packageRoot,
        dependencyName,
        pathRefs
      );
      if (!target) markReason(reasons, 'unresolved_declared_dependency');
      else addDependency(dependencies, item.ref, target, reasons);
    }
  }
  return { records, pathRefs, dependencies, appRoots };
}

function mergeBase(target, source) {
  for (const [ref, incoming] of source.records)
    target.records.set(ref, mergeComponent(target.records.get(ref), incoming));
  for (const [key, ref] of source.pathRefs) target.pathRefs.set(key, ref);
  for (const [ref, values] of source.dependencies) {
    for (const value of values)
      addDependency(target.dependencies, ref, value, target.reasons);
  }
  target.appRoots.push(...source.appRoots);
}

function loadBuildFile(context, reasons) {
  if (!buildFile) return null;
  const value = readJson(
    path.resolve(buildFile),
    context,
    reasons,
    'build_sbom'
  );
  if (
    !value ||
    value.bomFormat !== 'CycloneDX' ||
    value.specVersion !== '1.7'
  ) {
    markReason(reasons, 'invalid_build_sbom');
    return null;
  }
  return value;
}

function mergeBuild(records, dependencies, build, reasons) {
  if (!build) return;
  const byPurl = new Map();
  for (const component of records.values()) {
    if (!component.purl) continue;
    const list = byPurl.get(component.purl) || [];
    list.push(component.ref);
    byPurl.set(component.purl, list);
  }
  const references = new Map();
  const root = build.metadata?.component;
  if (root && typeof root === 'object' && root['bom-ref'])
    references.set(bounded(root['bom-ref'], 2048), applicationId);
  const components = Array.isArray(build.components) ? build.components : [];
  for (const value of components.slice(0, settings.maxEntries)) {
    if (!value || typeof value !== 'object') {
      markReason(reasons, 'invalid_declared_component');
      continue;
    }
    const oldRef = bounded(value['bom-ref'], 2048);
    const purl = bounded(value.purl, 2048);
    const matches = purl ? byPurl.get(purl) || [] : [];
    if (matches.length === 1) {
      const target = records.get(matches[0]);
      if (target) {
        target.declared = true;
        if (!target.licenses?.length)
          target.licenses = declaredLicenses(value.licenses);
        if (Array.isArray(value.hashes) && value.hashes.length)
          target.externalHashDeclared = true;
        if (oldRef) references.set(oldRef, target.ref);
      }
      continue;
    }
    if (matches.length > 1) markReason(reasons, 'ambiguous_declared_component');
    if (records.size >= settings.maxComponents - 1) {
      markReason(reasons, 'component_count_limit');
      break;
    }
    const name = bounded(value.name, 512) || 'unknown-declared-component';
    const version = bounded(value.version, 256);
    const group = bounded(value.group, 512);
    const ref = `urn:beacon:security:declared:${sha256([purl, group, name, version, oldRef].join('|'))}`;
    const component = createComponent({
      name,
      version,
      purl,
      group,
      root: `${buildFile}|${oldRef}`,
      source: 'build-sbom',
      installed: false,
      declared: true,
      licenses: declaredLicenses(value.licenses),
    });
    component.ref = ref;
    component.packageRoots = new Set();
    component.integrityStatus = 'declared';
    component.authenticityStatus = 'unverified';
    component.hashStatus =
      Array.isArray(value.hashes) && value.hashes.length
        ? 'declared'
        : 'unavailable';
    component.externalHashDeclared =
      Array.isArray(value.hashes) && value.hashes.length > 0;
    records.set(ref, component);
    if (oldRef) references.set(oldRef, ref);
  }
  const dependencyValues = Array.isArray(build.dependencies)
    ? build.dependencies
    : [];
  for (const value of dependencyValues.slice(0, settings.maxEntries)) {
    if (!value || typeof value !== 'object') continue;
    const from = references.get(bounded(value.ref, 2048));
    if (!from || !Array.isArray(value.dependsOn)) {
      markReason(reasons, 'unresolved_declared_dependency');
      continue;
    }
    for (const target of value.dependsOn.slice(0, settings.maxEntries)) {
      const mapped = references.get(bounded(target, 2048));
      if (!mapped) markReason(reasons, 'unresolved_declared_dependency');
      else addDependency(dependencies, from, mapped, reasons);
    }
  }
}

function applicationRecord() {
  const service =
    identity.service && typeof identity.service === 'object'
      ? identity.service
      : {};
  const name =
    bounded(service['service.name'] || service.name, 512) || applicationId;
  const version = bounded(service['service.version'] || service.version, 256);
  const result = { type: 'application', 'bom-ref': applicationId, name };
  if (version) result.version = version;
  const values = [];
  for (const [prefix, source] of [
    ['otel:', service],
    ['code:', identity.code],
    ['runtime:', identity.runtime],
  ]) {
    if (!source || typeof source !== 'object') continue;
    for (const [key, value] of Object.entries(source).slice(0, 128)) {
      if (
        typeof value === 'string' ||
        typeof value === 'number' ||
        typeof value === 'boolean'
      )
        values.push(property(`${prefix}${key}`, value));
    }
  }
  values.push(
    property(
      'beacon:security:identity-status',
      identity.identity_status || 'incomplete'
    )
  );
  if (values.length) result.properties = values.slice(0, 192);
  return result;
}

function componentRecord(component) {
  const result = {
    type: 'library',
    'bom-ref': component.ref,
    name: component.name,
  };
  if (component.group) result.group = component.group;
  if (component.version) result.version = component.version;
  if (component.purl) result.purl = component.purl;
  if (component.artifactHash)
    result.hashes = [{ alg: 'SHA-256', content: component.artifactHash }];
  const properties = [
    property('beacon:security:sbom:identity-source', component.source),
    property(
      'beacon:security:sbom:deployed',
      component.installed ? 'true' : component.declared ? 'unknown' : 'false'
    ),
    property(
      'beacon:security:sbom:declared',
      component.declared ? 'true' : 'false'
    ),
    property('beacon:security:sbom:lifecycle', 'current'),
    property(
      'beacon:security:sbom:loaded',
      component.loaded ? 'true' : 'false'
    ),
    property(
      'beacon:security:sbom:integrity-status',
      component.integrityStatus
    ),
    property(
      'beacon:security:sbom:authenticity-status',
      component.authenticityStatus
    ),
    property('beacon:security:sbom:hash-status', component.hashStatus),
    // A coordinate identifies a package, but an installed directory alone
    // does not authenticate the artifact. Keep identity incomplete until a
    // real local artifact digest exists.
    property(
      'beacon:security:sbom:identity-status',
      component.purl && component.version && component.artifactHash
        ? 'complete'
        : 'incomplete'
    ),
    property(
      'beacon:security:sbom:coordinate-status',
      component.purl && component.version ? 'complete' : 'incomplete'
    ),
  ];
  if (component.integrity)
    properties.push(
      property('beacon:security:sbom:declared-integrity', component.integrity)
    );
  if (component.externalHashDeclared)
    properties.push(
      property('beacon:security:sbom:hash-source', 'build-sbom-declaration')
    );
  if (!component.version)
    properties.push(property('beacon:security:sbom:version-status', 'unknown'));
  result.properties = properties;
  if (component.licenses?.length)
    result.licenses = component.licenses.slice(0, 16);
  const locations = [...component.packageRoots]
    .slice(0, 32)
    .map(pathLabel)
    .filter(Boolean);
  if (locations.length)
    result.evidence = {
      occurrences: locations.map(location => ({ location })),
    };
  return result;
}

function quality(records) {
  const result = emptyQuality();
  result.components = records.size;
  for (const component of records.values()) {
    result.with_purl += component.purl ? 1 : 0;
    result.with_version += component.version ? 1 : 0;
    result.with_hash += component.artifactHash ? 1 : 0;
    result.with_license += component.licenses?.length ? 1 : 0;
    result.loaded_components += component.loaded ? 1 : 0;
  }
  return result;
}

function releaseId(records) {
  const hashes = recordEntries(records)
    .map(item => item.artifactHash)
    .filter(Boolean)
    .sort();
  const status = hashes.length ? 'artifact_digest' : 'incomplete';
  return {
    id: `release-${sha256(`${applicationId}|${hashes.join('|')}`)}`,
    status,
  };
}

function dependencyRecords(dependencies) {
  return [...dependencies.entries()]
    .map(([ref, values]) => ({ ref, dependsOn: [...values].sort() }))
    .filter(item => item.dependsOn.length)
    .sort((left, right) => left.ref.localeCompare(right.ref));
}

function toDocument(
  revision,
  records,
  dependencies,
  reasons,
  release,
  contentSha256,
  app,
  componentRecords
) {
  const qualityValue = quality(records);
  const properties = [
    property('source', 'beacon_security'),
    property('beacon:security:application-id', applicationId),
    property('beacon:security:release-id', release.id),
    property('beacon:security:release:identity-status', release.status),
    property('beacon:security:sbom:quality', JSON.stringify(qualityValue)),
    property('beacon:security:process-instance-id', identity.instance_id || ''),
    property(
      'beacon:security:sbom:completeness-reasons',
      [...reasons].sort().join(',')
    ),
    property(
      'beacon:security:sbom:loaded-semantics',
      'runtime_load_observed_not_execution'
    ),
    property('beacon:security:sbom:content-sha256', contentSha256),
  ];
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: sbomId,
    version: revision,
    metadata: {
      timestamp: nowIso(),
      lifecycles: [{ phase: 'operations' }],
      component: app,
      tools: {
        components: [
          {
            type: 'application',
            name: 'Beacon Security',
            version: toolVersion || '1.2.0',
          },
        ],
      },
    },
    components: componentRecords,
    dependencies: dependencyRecords(dependencies),
    compositions: [{ aggregate: 'incomplete', assemblies: [applicationId] }],
    properties,
  };
}

function historyDocument(revision, release) {
  return {
    schema_version: 1,
    source: 'beacon_security',
    sbom_id: sbomId,
    revision,
    application_id: applicationId,
    release_id: release.id,
    updated_at: nowIso(),
    entries: [...state.history.values()].sort((left, right) =>
      left['bom-ref'].localeCompare(right['bom-ref'])
    ),
    history_limit: Math.max(0, settings.maxComponents - 1),
    history_complete:
      state.history.size < Math.max(0, settings.maxComponents - 1),
  };
}

function writeJsonAtomic(filename, value) {
  const parent = path.dirname(filename);
  fs.mkdirSync(parent, { recursive: true });
  const temporary = path.join(
    parent,
    `.${path.basename(filename)}.${process.pid}.${crypto.randomUUID()}.tmp`
  );
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    return temporary;
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {}
    }
    try {
      fs.unlinkSync(temporary);
    } catch {}
    throw error;
  }
}

function writePair(document, history) {
  const parent = path.dirname(output);
  fs.mkdirSync(parent, { recursive: true });
  let documentTemp = '';
  let historyTemp = '';
  const documentBackup = `${output}.${process.pid}.${crypto.randomUUID()}.old`;
  const historyBackup = `${historyPath}.${process.pid}.${crypto.randomUUID()}.old`;
  let documentMoved = false;
  let historyMoved = false;
  let documentBacked = false;
  let historyBacked = false;
  try {
    documentTemp = writeJsonAtomic(output, document);
    historyTemp = writeJsonAtomic(historyPath, history);
    if (safeStat(output)) {
      fs.renameSync(output, documentBackup);
      documentBacked = true;
    }
    if (safeStat(historyPath)) {
      fs.renameSync(historyPath, historyBackup);
      historyBacked = true;
    }
    fs.renameSync(documentTemp, output);
    documentMoved = true;
    fs.renameSync(historyTemp, historyPath);
    historyMoved = true;
    try {
      const dir = fs.openSync(parent, 'r');
      try {
        fs.fsyncSync(dir);
      } finally {
        fs.closeSync(dir);
      }
    } catch {}
    if (documentBacked) {
      try {
        fs.unlinkSync(documentBackup);
      } catch {}
    }
    if (historyBacked) {
      try {
        fs.unlinkSync(historyBackup);
      } catch {}
    }
  } catch (error) {
    if (documentMoved) {
      try {
        fs.unlinkSync(output);
      } catch {}
    }
    if (historyMoved) {
      try {
        fs.unlinkSync(historyPath);
      } catch {}
    }
    if (documentBacked) {
      try {
        fs.renameSync(documentBackup, output);
      } catch {}
    }
    if (historyBacked) {
      try {
        fs.renameSync(historyBackup, historyPath);
      } catch {}
    }
    throw error;
  } finally {
    for (const filename of [
      documentTemp,
      historyTemp,
      documentBackup,
      historyBackup,
    ]) {
      try {
        fs.unlinkSync(filename);
      } catch {}
    }
  }
}

function loadExistingHistory(context, reasons) {
  if (state.historyLoaded) return;
  state.historyLoaded = true;
  if (!safeStat(historyPath)) return;
  const value = readJson(historyPath, context, reasons, 'history');
  if (!value || !Array.isArray(value.entries)) return;
  for (const entry of value.entries.slice(
    0,
    Math.max(0, settings.maxComponents - 1)
  )) {
    if (entry && typeof entry === 'object' && entry['bom-ref'])
      state.history.set(bounded(entry['bom-ref'], 2048), { ...entry });
  }
}

function observeMapping(base, reasons) {
  const byPath = Object.create(null);
  const byUrl = Object.create(null);
  // The application component is known from the published package root even
  // before a loader observation reaches this worker.  Keeping roots in the
  // immutable snapshot lets a finding emitted during startup resolve its
  // generated source file without scanning the main thread or inventing a
  // third-party package identity.
  const applicationRoots = base.appRoots
    .slice(0, 256)
    .map(root => path.resolve(root));
  const packageRoots = new Map();
  for (const component of base.records.values()) {
    for (const root of component.packageRoots) {
      const normalized = path.resolve(root);
      if (!packageRoots.has(normalized))
        packageRoots.set(normalized, component);
    }
  }
  const appRoots = new Set(base.appRoots.map(root => path.resolve(root)));
  const closestRoot = (filename, roots) => {
    let current = path.resolve(filename);
    while (!roots.has(current)) {
      const parent = path.dirname(current);
      if (parent === current) return undefined;
      current = parent;
    }
    return current;
  };
  const mapFor = (pathName, urlValue, query) => {
    const stat = safeStat(pathName);
    if (!stat?.isFile()) {
      markReason(reasons, 'observed_file_unreadable');
      return;
    }
    const actual = realPath(pathName) || pathName;
    // Walk ancestors so nested node_modules wins without scanning every package.
    const best = packageRoots.get(closestRoot(actual, packageRoots));
    if (best) {
      best.loaded = true;
      const resolved = {
        status: 'resolved',
        'bom-ref': best.ref,
        source: actual,
        observed_url: urlValue,
        query: query || '',
      };
      byPath[pathName] = resolved;
      byPath[actual] = resolved;
      if (urlValue) byUrl[urlValue] = resolved;
      return;
    }
    const appRoot = closestRoot(actual, appRoots);
    if (appRoot) {
      const resolved = {
        status: 'resolved',
        'bom-ref': applicationId,
        source: actual,
        observed_url: urlValue,
        query: query || '',
      };
      byPath[pathName] = resolved;
      byPath[actual] = resolved;
      if (urlValue) byUrl[urlValue] = resolved;
      return;
    }
    const unresolved = {
      status: 'unresolved',
      reason: 'unresolved_package_path',
      source: actual,
      observed_url: urlValue,
      query: query || '',
    };
    byPath[pathName] = unresolved;
    byPath[actual] = unresolved;
    if (urlValue) byUrl[urlValue] = unresolved;
    markReason(reasons, 'unresolved_observed_module');
  };
  for (const raw of state.observations.values()) {
    const parsed = parseObserved(raw);
    if (parsed.reason) {
      markReason(reasons, `observation_${parsed.reason}`);
      continue;
    }
    mapFor(parsed.path, parsed.url, parsed.query);
  }
  return { byPath, byUrl, applicationRoots };
}

function discover() {
  const context = { entries: 0, scanBytes: 0 };
  const reasons = new Set(['runtime_dependency_graph_incomplete']);
  const base = {
    records: new Map(),
    pathRefs: new Map(),
    dependencies: new Map(),
    appRoots: [],
    reasons,
  };
  const roots = include.length ? include : [process.cwd()];
  const canonicalRoots = [];
  for (const rootValue of roots) {
    if (!addEntry(context, reasons)) break;
    const root = path.resolve(rootValue);
    const appRoot = appPackageRoot(root, context, reasons);
    if (!appRoot) continue;
    if (!canonicalRoots.includes(appRoot)) canonicalRoots.push(appRoot);
  }
  const rootKey = canonicalRoots.join('|');
  const fingerprint = canonicalRoots
    .map(root => {
      const packageFile = path.join(root, 'package.json');
      const lockFile = path.join(root, 'package-lock.json');
      const packageStat = safeStat(packageFile);
      const lockStat = safeStat(lockFile);
      return `${root}|${packageStat?.size || 0}|${packageStat?.mtimeMs || 0}|${lockStat?.size || 0}|${lockStat?.mtimeMs || 0}`;
    })
    .join('|');
  if (
    state.baseCache &&
    state.baseCacheKey === `${rootKey}|${fingerprint}` &&
    Date.now() - state.baseCacheAt < settings.cacheSeconds * 1000
  ) {
    return { ...state.baseCache, reasons: new Set(state.baseCache.reasons) };
  }
  for (const root of canonicalRoots) {
    const result = discoverRoot(root, context, reasons);
    mergeBase(base, result);
  }
  base.reasons = reasons;
  state.baseCache = {
    records: new Map(
      [...base.records].map(([key, value]) => [key, cloneComponent(value)])
    ),
    pathRefs: new Map(base.pathRefs),
    dependencies: new Map(
      [...base.dependencies].map(([key, values]) => [key, new Set(values)])
    ),
    appRoots: [...base.appRoots],
    reasons: new Set(reasons),
    budget: { entries: context.entries, scanBytes: context.scanBytes },
  };
  state.baseCacheKey = `${rootKey}|${fingerprint}`;
  state.baseCacheAt = Date.now();
  base.budget = { entries: context.entries, scanBytes: context.scanBytes };
  return base;
}

function cloneComponent(component) {
  return {
    ...component,
    packageRoots: new Set(component.packageRoots),
    dependencies: new Set(component.dependencies),
    dependencyNames: [...component.dependencyNames],
    licenses:
      component.licenses?.map(item => ({
        ...item,
        license: item.license ? { ...item.license } : undefined,
      })) || [],
  };
}

function snapshotPayload(
  records,
  dependencies,
  reasons,
  mapping,
  release,
  contentSha256
) {
  return {
    revision: state.published.revision,
    release_id: release.id,
    content_sha256: contentSha256,
    byPath: mapping.byPath,
    byUrl: mapping.byUrl,
    application_roots: mapping.applicationRoots,
    quality: quality(records),
    reasons: [...reasons].sort(),
    component_count: records.size,
  };
}

function updateHistory(recordDigests) {
  const previous = state.previousDigests;
  for (const [ref, digest] of recordDigests) {
    if (previous.get(ref) === digest) continue;
    let historical = state.history.get(ref);
    if (
      !historical &&
      state.history.size < Math.max(0, settings.maxComponents - 1)
    ) {
      historical = { 'bom-ref': ref, first_seen: nowIso() };
      state.history.set(ref, historical);
    }
    if (historical) {
      historical.state = 'current';
      historical.last_changed_at = nowIso();
    }
  }
  for (const ref of previous.keys()) {
    if (recordDigests.has(ref)) continue;
    const historical = state.history.get(ref);
    if (historical) {
      historical.state = 'removed';
      historical.last_changed_at = nowIso();
    }
  }
}

function health(status, reasons) {
  return {
    event_name: 'beacon.security.sbom.health',
    status,
    sbom_id: sbomId,
    revision: state.published.revision,
    application_id: applicationId,
    release_id: state.published.releaseId,
    instance_id: bounded(identity.instance_id, 1024),
    last_refresh_at: state.lastSuccessAt || null,
    last_failure_at: state.lastFailureAt || null,
    last_error_type: state.lastErrorType || null,
    current_components: state.published.componentCount,
    history_count: state.history.size,
    completeness: 'incomplete',
    reasons: [...(reasons || state.published.reasons)].sort(),
  };
}

function publish() {
  if (state.closing) return;
  if (state.refreshing) {
    state.refreshAgain = true;
    return;
  }
  state.refreshing = true;
  try {
    const base = discover();
    const reasons = new Set(
      base.reasons || ['runtime_dependency_graph_incomplete']
    );
    const records = new Map(
      [...base.records].map(([key, value]) => [key, cloneComponent(value)])
    );
    const dependencies = new Map(
      [...base.dependencies].map(([key, values]) => [key, new Set(values)])
    );
    const mapping = observeMapping(
      { records, appRoots: base.appRoots },
      reasons
    );
    const context = {
      entries: base.budget?.entries || 0,
      scanBytes: base.budget?.scanBytes || 0,
    };
    if (localOutputEnabled) loadExistingHistory(context, reasons);
    const build = loadBuildFile(context, reasons);
    mergeBuild(records, dependencies, build, reasons);
    const release = releaseId(records);
    const app = applicationRecord();
    const stable = {
      application: app,
      records: recordEntries(records).map(componentRecord),
      dependencies: dependencyRecords(dependencies),
      reasons: [...reasons].sort(),
      release_id: release.id,
      mapping: {
        byPath: mapping.byPath,
        byUrl: mapping.byUrl,
        applicationRoots: mapping.applicationRoots,
      },
    };
    const contentSha256 = sha256(stableJson(stable));
    if (contentSha256 === state.published.contentSha256) {
      state.lastSuccessAt = nowIso();
      state.published.reasons = reasons;
      parentPort.postMessage({
        type: 'event',
        event: health('current', reasons),
      });
      return;
    }
    const revision = state.published.revision + 1;
    const document = toDocument(
      revision,
      records,
      dependencies,
      reasons,
      release,
      contentSha256,
      app,
      stable.records
    );
    const snapshotEvents = dependencySnapshot(
      {
        event_name: 'beacon.security.sbom.snapshot',
        status: 'current',
        sbom_id: sbomId,
        revision,
        application_id: applicationId,
        release_id: release.id,
        instance_id: bounded(identity.instance_id, 1024),
        completeness: 'incomplete',
        reasons: [...reasons].sort(),
      },
      stable.records,
      identity
    );
    const recordDigests = new Map(
      stable.records.map(record => [
        record['bom-ref'],
        sha256(stableJson(record)),
      ])
    );
    const historyBefore = new Map(
      [...state.history].map(([key, value]) => [key, { ...value }])
    );
    updateHistory(recordDigests);
    const history = historyDocument(revision, release);
    if (localOutputEnabled) {
      try {
        writePair(document, history);
      } catch (error) {
        state.history = historyBefore;
        throw error;
      }
    }
    state.previousDigests = recordDigests;
    state.published = {
      revision,
      releaseId: release.id,
      contentSha256,
      componentCount: records.size,
      reasons,
      quality: quality(records),
    };
    state.lastSuccessAt = nowIso();
    parentPort.postMessage({
      type: 'published',
      snapshot: snapshotPayload(
        records,
        dependencies,
        reasons,
        mapping,
        release,
        contentSha256
      ),
      events: [...snapshotEvents, health('current', reasons)],
    });
  } catch (error) {
    state.lastFailureAt = nowIso();
    state.lastErrorType = bounded(error?.name || 'Error', 256);
    parentPort.postMessage({
      type: 'event',
      event: {
        event_name: 'beacon.security.sbom.update_failed',
        sbom_id: sbomId,
        revision: state.published.revision,
        release_id: state.published.releaseId,
        error_type: state.lastErrorType,
      },
    });
    parentPort.postMessage({
      type: 'event',
      event: health(
        'degraded',
        new Set([...state.published.reasons, 'update_failed'])
      ),
    });
  } finally {
    state.refreshing = false;
    if (state.refreshAgain && !state.closing) {
      state.refreshAgain = false;
      scheduleRefresh(0);
    } else if (state.closeAfterRefresh) finishClose();
  }
}

function scheduleRefresh(delay = 10) {
  if (state.closing) return;
  if (state.pendingTimer) return;
  state.pendingTimer = setTimeout(() => {
    state.pendingTimer = null;
    publish();
  }, delay);
  state.pendingTimer.unref?.();
}

function finishClose() {
  state.closing = true;
  if (state.pendingTimer) clearTimeout(state.pendingTimer);
  parentPort.postMessage({ type: 'closed' });
  parentPort.close();
}

parentPort.on('message', message => {
  if (!message || typeof message !== 'object') return;
  const observeOne = raw => {
    const value = bounded(raw, 4096);
    if (!value) return { accepted: 0, dropped: 0 };
    const key = value;
    let dropped = 0;
    if (
      !state.observations.has(key) &&
      state.observations.size >= settings.maxQueue
    ) {
      const oldest = state.observations.keys().next().value;
      if (oldest !== undefined) {
        state.observations.delete(oldest);
        dropped = 1;
      }
      scheduleRefresh(0);
    }
    state.observations.set(key, value);
    scheduleRefresh(10);
    return { accepted: 1, dropped };
  };
  if (message.type === 'observe_batch') {
    const values = Array.isArray(message.values)
      ? message.values.slice(0, 64)
      : [];
    let accepted = 0;
    let dropped = 0;
    for (const value of values) {
      const result = observeOne(value);
      accepted += result.accepted;
      dropped += result.dropped;
    }
    parentPort.postMessage({
      type: 'observe_ack',
      accepted,
      dropped,
      queue_size: state.observations.size,
    });
  } else if (message.type === 'observe') {
    const result = observeOne(message.value);
    parentPort.postMessage({
      type: 'observe_ack',
      accepted: result.accepted,
      dropped: result.dropped,
      queue_size: state.observations.size,
    });
  } else if (message.type === 'refresh') {
    scheduleRefresh(0);
  } else if (message.type === 'close') {
    if (state.refreshing) state.closeAfterRefresh = true;
    else if (state.pendingTimer) {
      // Observations are delivered over the same MessagePort before close,
      // but their refresh is intentionally deferred to batch loader traffic.
      // Publish that pending batch before acknowledging shutdown so a fast
      // application cannot leave its final loaded modules out of the durable
      // snapshot and component mapping.
      clearTimeout(state.pendingTimer);
      state.pendingTimer = null;
      state.closeAfterRefresh = true;
      publish();
    } else finishClose();
  }
});

const interval = setInterval(
  () => scheduleRefresh(0),
  settings.refreshSeconds * 1000
);
interval.unref?.();
