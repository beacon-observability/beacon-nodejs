// Project runtime-owned v2 evidence without reserializing message.
// This internal producer boundary is not an arbitrary incoming-log validator.
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

const nonempty = value =>
  typeof value === 'string' && value.trim() !== '' ? value : '';

export function inventoryEventId(body) {
  const input = [
    body.source,
    body.event_name,
    body.instance_id,
    body.observed_at,
    String(body.part_index ?? 0),
  ];
  return `inventory-${createHash('sha256').update(JSON.stringify(input), 'utf8').digest('hex')}`;
}

export function siemEvent(raw, resource = {}, context = {}) {
  const body = JSON.parse(raw);
  const inventory = body.event_name === 'beacon.security.sbom.inventory';
  if (
    body.schema_version !== 2 ||
    (!inventory && body.event_name !== 'beacon.security.finding') ||
    body.source !== (inventory ? 'beacon_security_sbom' : 'beacon_security')
  )
    throw new Error('unsupported_security_event');
  const ip = nonempty(context.client_ip);
  return {
    time: body.observed_at,
    event_id: inventory ? inventoryEventId(body) : body.occurrence_id,
    event_class: inventory ? 'software_inventory_info' : 'security_finding',
    source: body.source,
    service: nonempty(resource['service.name']),
    tenant_id:
      nonempty(context.tenant_id) ||
      nonempty(resource['tenant.id']) ||
      'default',
    actor: inventory ? '' : nonempty(context.actor),
    ip: inventory || !isIP(ip) ? '' : ip,
    action: inventory ? 'inventory_snapshot' : body.rule,
    target: inventory ? body.instance_id : body.finding_id,
    target_type: inventory ? 'process' : 'finding',
    outcome: inventory ? 'success' : 'unknown',
    status: 'info',
    severity: 'informational',
    message: raw,
    ...Object.fromEntries(
      ['instance_id', 'trace_id', 'span_id', 'trace_flags']
        .filter(key => key in body)
        .map(key => [key, body[key]])
    ),
  };
}
