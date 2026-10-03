import { eventRecord } from '../schema.mjs';
import { limit } from '../config.mjs';

export function dependencySnapshot(event, records, identity) {
  const unique = new Map();
  for (const record of records) {
    if (
      record.type !== 'library' ||
      !record.properties?.some(
        item =>
          item.name === 'beacon:security:sbom:loaded' && item.value === 'true'
      )
    )
      continue;
    const dependency = { name: record.name, version: record.version || '' };
    if (!record.purl || !record.version) {
      const hash = record.hashes?.find(item => item.alg === 'SHA-256')?.content;
      if (hash) dependency.hash = hash;
    }
    unique.set(JSON.stringify(dependency), dependency);
  }
  const rows = [...unique]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, row]) => row);
  const envelope = eventRecord(
    {
      ...event,
      event_name: 'beacon.security.sbom.snapshot',
      component_count: rows.length,
      part_index: 2147483647,
      part_count: 2147483647,
      dependencies: [],
    },
    identity
  );
  const maximum = Math.min(
    limit('beacon.security.evidence.max.bytes', 65536),
    limit('beacon.security.export.sbom.bytes-per-second', 262144)
  );
  const overhead = Buffer.byteLength(JSON.stringify(envelope));
  if (overhead > maximum)
    throw new Error('dependency_snapshot_envelope_exceeds_budget');
  const chunks = [[]];
  let bytes = overhead;
  for (const row of rows) {
    const size = Buffer.byteLength(JSON.stringify(row));
    if (overhead + size > maximum)
      throw new Error('dependency_snapshot_item_exceeds_budget');
    let chunk = chunks.at(-1);
    if (bytes + size + (chunk.length ? 1 : 0) > maximum) {
      chunk = [];
      chunks.push(chunk);
      bytes = overhead;
    }
    bytes += size + (chunk.length ? 1 : 0);
    chunk.push(row);
  }
  return chunks.map((dependencies, part_index) => ({
    ...envelope,
    dependencies,
    part_index,
    part_count: chunks.length,
  }));
}
