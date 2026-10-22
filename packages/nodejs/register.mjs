/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

const enabled = ['true', '1', 'yes', 'on'].includes(
  (process.env.BEACON_SECURITY_ENABLED ?? '').trim().toLowerCase()
);

if (enabled) {
  const { setSecurityShutdown } = await import('./build/src/lifecycle.js');
  // Register shutdown before installation as a partially initialized Security
  // runtime may still own resources after a startup failure.
  const security = await import('@beacon-observability/security-nodejs');
  setSecurityShutdown(() => security.shutdown());
  await import('@beacon-observability/security-nodejs/register');
} else {
  const { register } = await import('node:module');
  register('@opentelemetry/instrumentation/hook.mjs', import.meta.url);
}

await import('./build/src/register.js');
