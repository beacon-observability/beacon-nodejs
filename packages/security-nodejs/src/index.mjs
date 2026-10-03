import { Hook as RequireHook } from 'require-in-the-middle';
import { Hook as ImportHook } from 'import-in-the-middle';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { VERSION, flag, instrumentationEnabled } from './config.mjs';
import { install } from './bootstrap.mjs';
import { getRuntime, startupGap } from './core/runtime.mjs';
import { installFramework } from './adapters/frameworks.mjs';
import { installBuiltins, installLibrary } from './adapters/sinks.mjs';
export { shutdown } from './core/runtime.mjs';

let singleton;
const libraries = [
  'express',
  'express4',
  'fastify',
  'pg',
  'mysql2',
  'mysql2/promise',
  'undici',
];
const majors = {
  express: [4, 5],
  express4: [4],
  fastify: [5],
  pg: [8],
  mysql2: [3],
  'mysql2/promise': [3],
  undici: [8],
};
const versions = new Map();
function patch(exports, name, directory) {
  try {
    if (!libraries.includes(name)) return exports;
    if (!versions.has(directory))
      versions.set(
        directory,
        JSON.parse(readFileSync(path.join(directory, 'package.json'), 'utf8'))
          .version
      );
    const version = versions.get(directory);
    if (!majors[name].includes(Number(version?.split('.')[0]))) {
      startupGap('unsupported_adapter_version:' + name);
      return exports;
    }
    return name.startsWith('express') || name === 'fastify'
      ? installFramework(
          name.startsWith('express') ? 'express' : name,
          exports,
          version
        )
      : installLibrary(name, exports, version);
  } catch {
    startupGap('adapter_registration_failed:' + name);
    return exports;
  }
}

// InstrumentationBase would create OTel's catch-all require cache before the
// host imports its SDK, caching HTTP before HttpInstrumentation is registered.
// Scoped hooks keep that lifecycle under the host's control.
export class SecurityInstrumentation {
  instrumentationName = 'io.beacon.security';
  instrumentationVersion = VERSION;
  constructor(config = {}) {
    if (singleton) return singleton;
    singleton = this;
    this.config = {
      enabled: config.enabled ?? flag('beacon.security.enabled', false),
    };
    this.installed = false;
    if (this.config.enabled) this._install();
  }
  _install() {
    if (this.installed) return;
    this.installed = true;
    install();
    installBuiltins();
    this.requireHook = new RequireHook(libraries, { internals: false }, patch);
    this.importHook = new ImportHook(libraries, { internals: false }, patch);
  }
  enable() {
    this._install();
    this.config.enabled = true;
    instrumentationEnabled(true);
  }
  disable() {
    this.config.enabled = false;
    instrumentationEnabled(false);
  }
  isEnabled() {
    return this.config.enabled;
  }
  getConfig() {
    return { ...this.config };
  }
  setConfig(config) {
    this.config = { ...this.config, ...config };
    this.config.enabled === false ? this.disable() : this.enable();
  }
  setTracerProvider(provider) {
    this.tracerProvider = provider;
  }
  setMeterProvider(provider) {
    this.meterProvider = provider;
  }
  setLoggerProvider(provider) {
    const runtime = getRuntime();
    if (runtime)
      runtime.exporter.explicitLogger = provider.getLogger(
        this.instrumentationName,
        VERSION
      );
  }
}
