/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

let securityShutdown: (() => Promise<void>) | undefined;

/** Installed by the ESM preload before the shared SDK is started. */
export function setSecurityShutdown(shutdown: () => Promise<void>): void {
  securityShutdown = shutdown;
}

export async function shutdownSecurity(): Promise<void> {
  await securityShutdown?.();
}
