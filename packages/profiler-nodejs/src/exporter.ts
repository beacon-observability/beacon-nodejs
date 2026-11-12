/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Client, credentials, Metadata } from '@grpc/grpc-js';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { diag } from '@opentelemetry/api';
import { encodeProfiles, profilesResponse } from './otlp';
import type {
  OtlpProfilingExporterOptions,
  ProfileBatch,
  ProfileExporter,
  FileProfilingExporterOptions,
} from './types';

export class OtlpProfilingExporter implements ProfileExporter {
  private readonly endpoint: string;
  private readonly client?: Client;
  private readonly timeoutMillis: number;
  private readonly headers: Record<string, string>;
  private readonly fetchImpl: typeof fetch;

  constructor(options: OtlpProfilingExporterOptions) {
    const url = new URL(options.endpoint);
    if (!['http:', 'https:'].includes(url.protocol))
      throw new Error('OTLP Profiles requires an HTTP(S) endpoint');
    this.endpoint = url.toString();
    if (options.protocol === 'grpc') {
      if (url.pathname !== '/' || url.search || url.hash)
        throw new Error(
          'gRPC Profiles endpoint must contain only scheme and host:port'
        );
      this.client = new Client(
        url.host,
        url.protocol === 'http:'
          ? credentials.createInsecure()
          : credentials.createSsl()
      );
    }
    this.timeoutMillis = options.timeoutMillis ?? 10000;
    if (
      !Number.isFinite(this.timeoutMillis) ||
      this.timeoutMillis < 1 ||
      this.timeoutMillis > 2147483647
    )
      throw new Error(
        'OTLP Profiles timeout must be between 1 and 2147483647 milliseconds'
      );
    this.headers = options.headers ?? {};
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function')
      throw new Error('global fetch is not available');
  }

  public async export(batch: ProfileBatch): Promise<void> {
    if (this.client) {
      const metadata = new Metadata();
      for (const [key, value] of Object.entries(this.headers))
        metadata.set(key, value);
      const response = await new Promise<Uint8Array>((resolve, reject) => {
        this.client!.makeUnaryRequest(
          '/opentelemetry.proto.collector.profiles.v1development.ProfilesService/Export',
          (value: Uint8Array) => Buffer.from(value),
          (value: Buffer) => value,
          encodeProfiles(batch),
          metadata,
          { deadline: Date.now() + this.timeoutMillis },
          (error, value) => (error ? reject(error) : resolve(value!))
        );
      });
      this.checkResponse(response);
      return;
    }
    const response = await this.fetchImpl(this.endpoint, {
      method: 'POST',
      body: new Uint8Array(encodeProfiles(batch)),
      headers: { ...this.headers, 'Content-Type': 'application/x-protobuf' },
      signal: AbortSignal.timeout(this.timeoutMillis),
      redirect: 'error',
    });
    if (!response.ok)
      throw new Error(
        `profiling export failed: ${response.status} ${response.statusText}`
      );
    const body = new Uint8Array(await response.arrayBuffer());
    this.checkResponse(body);
  }

  private checkResponse(body: Uint8Array): void {
    const result = profilesResponse.toObject(profilesResponse.decode(body), {
      longs: String,
    });
    if (result.partialSuccess) {
      const partial = result.partialSuccess;
      if (partial.rejectedProfiles && partial.rejectedProfiles !== '0')
        throw new Error(
          `OTLP Profiles rejected ${partial.rejectedProfiles} profiles: ${partial.errorMessage ?? ''}`
        );
      if (partial.errorMessage)
        diag.warn(`OTLP Profiles: ${partial.errorMessage}`);
    }
  }

  public async shutdown(): Promise<void> {
    this.client?.close();
  }
}

export class FileProfilingExporter implements ProfileExporter {
  constructor(private readonly options: FileProfilingExporterOptions) {}
  public async export(batch: ProfileBatch): Promise<void> {
    await mkdir(this.options.directory, { recursive: true });
    for (const profile of batch.profiles) {
      await writeFile(
        join(
          this.options.directory,
          `profile-${batch.startTime.getTime()}-${randomUUID()}.pprof`
        ),
        profile.data,
        { flag: 'wx' }
      );
    }
  }
  public async shutdown(): Promise<void> {}
}
