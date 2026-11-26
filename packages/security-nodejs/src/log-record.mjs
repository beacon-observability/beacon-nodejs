import { inventoryEventId } from './siem.mjs';

// Preserve integer nanoseconds; Date parsing alone discards sub-millisecond digits.
export function eventTime(value) {
  const match =
    typeof value === 'string' &&
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(
      value
    );
  if (!match) throw new Error('invalid_security_event_time');
  const calendar = Date.parse(`${match[1]}Z`);
  const milliseconds = Date.parse(`${match[1]}${match[3]}`);
  if (
    !Number.isFinite(milliseconds) ||
    !Number.isFinite(calendar) ||
    new Date(calendar).toISOString() !== `${match[1]}.000Z`
  )
    throw new Error('invalid_security_event_time');
  const nanoseconds =
    BigInt(milliseconds) * 1000000n + BigInt((match[2] || '').padEnd(9, '0'));
  if (nanoseconds <= 0n || nanoseconds > 9223372036854775807n)
    throw new Error('invalid_security_event_time');
  return nanoseconds;
}

export function logRecord(event) {
  const inventory = event.event_name === 'beacon.security.sbom.inventory';
  if (
    event.schema_version !== 2 ||
    event.source !== (inventory ? 'beacon_security_sbom' : 'beacon_security') ||
    (!inventory && event.event_name !== 'beacon.security.finding')
  )
    throw new Error('unsupported_security_event');
  const time = eventTime(event.observed_at);
  const id = inventory ? inventoryEventId(event) : event.occurrence_id;
  if (typeof id !== 'string' || !id)
    throw new Error('missing_security_event_id');
  const { observed_at, occurrence_id, ...body } = event;
  return {
    time_unix_nano: String(time),
    body: JSON.stringify(body),
    attributes: {
      event_id: id,
      source: event.source,
      'event.name': event.event_name,
    },
  };
}
