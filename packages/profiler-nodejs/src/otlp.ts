/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { isAbsolute, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { Root } from 'protobufjs';
import { Profile } from 'pprof-format';
import type { ProfileBatch } from './types';

// Pinned OpenTelemetry Proto v1.11.0; shared dictionary Profiles schema.
const protoPath = existsSync(join(__dirname, '../proto'))
  ? join(__dirname, '../proto')
  : join(__dirname, '../../proto');
const root = new Root();
root.resolvePath = (_origin, target) =>
  isAbsolute(target) ? target : join(protoPath, target);
root.loadSync(
  'opentelemetry/proto/collector/profiles/v1development/profiles_service.proto'
);
export const profilesRequest = root.lookupType(
  'opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceRequest'
);
export const profilesResponse = root.lookupType(
  'opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceResponse'
);

export function encodeProfiles(batch: ProfileBatch): Uint8Array {
  const dictionary = {
    mappingTable: [{}] as object[],
    locationTable: [{}] as object[],
    functionTable: [{}] as object[],
    linkTable: [{}],
    stringTable: [''],
    attributeTable: [{}],
    stackTable: [{}] as object[],
  };
  const strings = new Map<string, number>([['', 0]]);
  const str = (value: string) => {
    let index = strings.get(value);
    if (index === undefined) {
      index = dictionary.stringTable.length;
      strings.set(value, index);
      dictionary.stringTable.push(value);
    }
    return index;
  };
  const profiles: object[] = [];
  for (const collected of batch.profiles) {
    const source = Profile.decode(gunzipSync(collected.data));
    const table = source.stringTable as typeof source.stringTable & {
      strings: string[];
    };
    const entries = Array.isArray(table.strings)
      ? table.strings
      : (source.stringTable as unknown as string[]);
    const text = (index: number | bigint) => entries[Number(index)] ?? '';
    const mappings = new Map<number | bigint, number>();
    for (const mapping of source.mapping) {
      mappings.set(mapping.id, dictionary.mappingTable.length);
      dictionary.mappingTable.push({
        memoryStart: String(mapping.memoryStart),
        memoryLimit: String(mapping.memoryLimit),
        fileOffset: String(mapping.fileOffset),
        filenameStrindex: str(text(mapping.filename)),
      });
    }
    const functions = new Map<number | bigint, number>();
    for (const fn of source.function) {
      functions.set(fn.id, dictionary.functionTable.length);
      dictionary.functionTable.push({
        nameStrindex: str(text(fn.name)),
        systemNameStrindex: str(text(fn.systemName)),
        filenameStrindex: str(text(fn.filename)),
        startLine: String(fn.startLine),
      });
    }
    const locations = new Map<number | bigint, number>();
    for (const location of source.location) {
      locations.set(location.id, dictionary.locationTable.length);
      dictionary.locationTable.push({
        mappingIndex: mappings.get(location.mappingId) ?? 0,
        address: String(location.address),
        lines: location.line.map(line => ({
          functionIndex: functions.get(line.functionId) ?? 0,
          line: String(line.line),
        })),
      });
    }
    const samples = source.sample.map(sample => {
      const stackIndex = dictionary.stackTable.length;
      dictionary.stackTable.push({
        locationIndices: sample.locationId.map(id => {
          const index = locations.get(id);
          if (index === undefined)
            throw new Error('pprof sample references an unknown location');
          return index;
        }),
      });
      const attributeIndices = sample.label.map(label => {
        const index = dictionary.attributeTable.length;
        dictionary.attributeTable.push({
          keyStrindex: str(text(label.key)),
          value: label.str
            ? { stringValue: text(label.str) }
            : { intValue: String(label.num) },
          unitStrindex: str(text(label.numUnit)),
        });
        return index;
      });
      return { stackIndex, attributeIndices };
    });
    // OTLP has one sample type per Profile; pprof's parallel values become separate Profiles.
    source.sampleType.forEach((type, index) => {
      profiles.push({
        sampleType: {
          typeStrindex: str(text(type.type)),
          unitStrindex: str(text(type.unit)),
        },
        timeUnixNano: String(BigInt(batch.startTime.getTime()) * 1000000n),
        durationNano: String(
          BigInt(
            Math.max(0, batch.endTime.getTime() - batch.startTime.getTime())
          ) * 1000000n
        ),
        profileId: randomBytes(16),
        periodType: source.periodType
          ? {
              typeStrindex: str(text(source.periodType.type)),
              unitStrindex: str(text(source.periodType.unit)),
            }
          : undefined,
        period: String(source.period ?? 0),
        samples: samples.map((sample, sampleIndex) => ({
          ...sample,
          values: [String(source.sample[sampleIndex].value[index] ?? 0)],
        })),
      });
    });
  }
  const identity: Record<string, string> = {
    service: 'service.name',
    version: 'service.version',
    env: 'deployment.environment.name',
    host: 'host.name',
    process_id: 'process.pid',
    runtime: 'process.runtime.name',
    runtime_version: 'process.runtime.version',
    language: 'telemetry.sdk.language',
  };
  return profilesRequest
    .encode(
      profilesRequest.fromObject({
        dictionary,
        resourceProfiles: [
          {
            resource: {
              attributes: Object.entries(batch.tags).map(([key, value]) => ({
                key: identity[key] ?? key,
                value:
                  key === 'process_id'
                    ? { intValue: value }
                    : { stringValue: value },
              })),
            },
            scopeProfiles: [
              {
                scope: { name: '@beacon-observability/profiler-nodejs' },
                profiles,
              },
            ],
          },
        ],
      })
    )
    .finish();
}
