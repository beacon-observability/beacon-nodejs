/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

const enabled = ['true', '1', 'yes', 'on'].includes(
  (process.env.BEACON_SECURITY_ENABLED ?? '').trim().toLowerCase()
);

if (enabled) {
  await import('@beacon-observability/security-nodejs/register');
}

await import('./build/src/register.js');
