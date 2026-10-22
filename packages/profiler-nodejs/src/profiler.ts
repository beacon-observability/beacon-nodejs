/*
 * Copyright The OpenTelemetry Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { diag } from '@opentelemetry/api';
import type { time } from '@datadog/pprof';
import type { Profile } from 'pprof-format';

import { buildCompatibleNodeProfiles } from './pprof';
import { buildProfilerTags } from './resource';
import type {
  CollectedProfile,
  NodeProfileType,
  NodeProfilingOptions,
  ProfileBatch,
  ProfileExporter,
} from './types';

const DEFAULT_INTERVAL_MILLIS = 60_000;
const DEFAULT_WALL_DURATION_MILLIS = 10_000;
const DEFAULT_HEAP_SAMPLING_INTERVAL_BYTES = 512 * 1024;
const DEFAULT_PROFILE_TYPES: NodeProfileType[] = ['wall', 'heap'];
const STACK_DEPTH = 64;
const SUPPORTS_CPED = Number(process.versions.node.split('.')[0]) >= 22;
const MAX_TIMER_MILLIS = 2_147_483_647;
let native: typeof import('@datadog/pprof') | undefined;
function nativeProfiler(): typeof import('@datadog/pprof') {
  return (native ??=
    require('@datadog/pprof') as typeof import('@datadog/pprof'));
}

function timerMillis(value: number, name: string): number {
  if (!Number.isFinite(value) || value < 1 || value > MAX_TIMER_MILLIS)
    throw new RangeError(
      `${name} must be between 1 and ${MAX_TIMER_MILLIS} milliseconds`
    );
  return Math.floor(value);
}

export class NodeProfiling {
  private readonly exporter: ProfileExporter;
  private readonly tags: Record<string, string>;
  private readonly profileTypes: NodeProfileType[];
  private readonly intervalMillis: number;
  private readonly wallDurationMillis: number;
  private readonly heapSamplingIntervalBytes: number;
  private readonly collectCpuTime: boolean;

  private timer?: NodeJS.Timeout;
  private collecting?: Promise<void>;
  private heapStarted = false;
  private cancelWall?: () => void;
  private shutdownPromise?: Promise<void>;

  constructor(options: NodeProfilingOptions) {
    this.exporter = options.exporter;
    this.tags = buildProfilerTags(options);
    this.profileTypes = options.profileTypes ?? DEFAULT_PROFILE_TYPES;
    this.intervalMillis = timerMillis(
      options.intervalMillis ?? DEFAULT_INTERVAL_MILLIS,
      'intervalMillis'
    );
    this.wallDurationMillis = timerMillis(
      options.wallDurationMillis ?? DEFAULT_WALL_DURATION_MILLIS,
      'wallDurationMillis'
    );
    this.heapSamplingIntervalBytes =
      options.heapSamplingIntervalBytes ?? DEFAULT_HEAP_SAMPLING_INTERVAL_BYTES;
    this.collectCpuTime =
      options.cpuProfilingEnabled ?? options.collectCpuTime ?? true;
  }

  async start(): Promise<void> {
    if (this.shutdownPromise) {
      await this.shutdownPromise;
      this.shutdownPromise = undefined;
    }
    if (this.timer !== undefined) {
      return;
    }

    if (this.profileTypes.length) nativeProfiler();
    this.ensureHeapProfiler();
    this.collectInBackground();
    this.timer = setInterval(
      () => this.collectInBackground(),
      this.intervalMillis
    );
    this.timer.unref?.();
  }

  async collectOnce(): Promise<void> {
    if (this.collecting) return this.collecting;
    this.collecting = this.collect(false).finally(() => {
      this.collecting = undefined;
    });
    return this.collecting;
  }

  private async collect(background: boolean): Promise<void> {
    this.ensureHeapProfiler();

    const startTime = new Date();
    const rawProfiles: Array<{ type: NodeProfileType; profile: Profile }> = [];

    if (this.profileTypes.includes('wall')) {
      const options = {
        durationMillis: Math.min(this.wallDurationMillis, this.intervalMillis),
        collectCpuTime: this.collectCpuTime,
        useCPED: this.collectCpuTime && SUPPORTS_CPED,
        withContexts: this.collectCpuTime,
      };
      const wallProfile = await this.collectWall(options, background);
      if (wallProfile === undefined) return;
      rawProfiles.push({ type: 'wall', profile: wallProfile });
    }

    if (this.profileTypes.includes('heap')) {
      rawProfiles.push({
        type: 'heap',
        profile: nativeProfiler().heap.profile(),
      });
    }

    const endTime = new Date();
    if (rawProfiles.length === 0) {
      diag.debug('No profile types were enabled, skipping export');
      return;
    }

    const profiles: CollectedProfile[] =
      buildCompatibleNodeProfiles(rawProfiles);

    const batch: ProfileBatch = {
      startTime,
      endTime,
      family: 'nodejs',
      format: 'pprof',
      tags: this.tags,
      profiles,
    };

    await this.exporter.export(batch);
  }

  shutdown(): Promise<void> {
    return (this.shutdownPromise ??= this.stop());
  }

  private async stop(): Promise<void> {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }

    this.cancelWall?.();
    await this.collecting;

    if (this.heapStarted) {
      nativeProfiler().heap.stop();
      this.heapStarted = false;
    }

    await this.exporter.shutdown?.();
  }

  private collectWall(
    options: NonNullable<Parameters<typeof time.profile>[0]>,
    background: boolean
  ): Promise<Profile | undefined> {
    return new Promise((resolve, reject) => {
      const { time } = nativeProfiler();
      time.start(options);
      let stopped = false;
      const finish = (cancelled: boolean) => {
        if (stopped) return;
        stopped = true;
        clearTimeout(timer);
        this.cancelWall = undefined;
        try {
          const profile = time.stop();
          resolve(cancelled ? undefined : profile);
        } catch (error) {
          reject(error);
        }
      };
      const timer = setTimeout(() => finish(false), options.durationMillis);
      if (background) timer.unref();
      this.cancelWall = () => finish(true);
    });
  }

  private ensureHeapProfiler(): void {
    if (!this.profileTypes.includes('heap') || this.heapStarted) {
      return;
    }

    nativeProfiler().heap.start(this.heapSamplingIntervalBytes, STACK_DEPTH);
    this.heapStarted = true;
  }

  private collectInBackground(): void {
    if (this.collecting !== undefined) {
      return;
    }
    this.collecting = this.collect(true)
      .catch(error => {
        diag.error('Node profiling collection failed', error);
      })
      .finally(() => {
        this.collecting = undefined;
      });
  }
}
