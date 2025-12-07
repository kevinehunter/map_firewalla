/**
 * Field Mapper
 *
 * Translates user-friendly field names to Firewalla API field names.
 * This allows users to use intuitive field names while the API receives
 * the correct field format.
 */

/**
 * Mapping from user-friendly field names to Firewalla API field names.
 * The API uses dotted notation (device.ip) while users may prefer
 * underscored names (device_ip) or simplified names (source_ip).
 */
export const FIELD_MAPPINGS: Record<string, string> = {
  // IP address fields
  source_ip: 'device.ip',
  src_ip: 'device.ip',
  destination_ip: 'remote.ip',
  dest_ip: 'remote.ip',
  dst_ip: 'remote.ip',
  device_ip: 'device.ip',
  remote_ip: 'remote.ip',

  // Device fields
  device_id: 'device.id',
  device_name: 'device.name',
  device_mac: 'device.id',
  mac: 'device.id',
  mac_address: 'device.id',

  // Network fields
  device_network: 'device.network.name',
  network_name: 'device.network.name',
  network_id: 'device.network.id',

  // Remote/destination fields
  remote_domain: 'remote.domain',
  remote_category: 'remote.category',
  remote_region: 'remote.region',
  dest_domain: 'remote.domain',
  destination_domain: 'remote.domain',

  // Box fields
  box_name: 'box.name',
  box_id: 'gid',
};

/**
 * Fields that should pass through without translation.
 * These are already in the correct API format.
 * Exported for use in validation and documentation.
 */
export const PASSTHROUGH_FIELDS = new Set([
  // Already dotted API fields
  'device.id',
  'device.ip',
  'device.name',
  'device.network.id',
  'device.network.name',
  'remote.ip',
  'remote.domain',
  'remote.category',
  'remote.region',
  'box.name',
  'gid',
  // Standard fields that don't need translation
  'protocol',
  'port',
  'direction',
  'blocked',
  'bytes',
  'download',
  'upload',
  'duration',
  'timestamp',
  'region',
  'category',
  'domain',
  'severity',
  'type',
  'status',
  'country',
  'country_code',
  'continent',
  'city',
  'timezone',
  'isp',
  'organization',
  'asn',
  'is_cloud_provider',
  'is_cloud',
  'is_proxy',
  'is_vpn',
  'geographic_risk_score',
  'online',
  'name',
  'ip',
  'id',
]);

/**
 * Translate a user-friendly field name to the Firewalla API field name.
 *
 * @param field - The user-provided field name
 * @returns The API field name (translated if mapping exists, otherwise unchanged)
 */
export function translateFieldName(field: string): string {
  // Check if there's a direct mapping
  const mapped = FIELD_MAPPINGS[field.toLowerCase()];
  if (mapped) {
    return mapped;
  }

  // Return as-is if it's a passthrough field or unknown
  return field;
}

/**
 * Translate all field names in a query string.
 * Handles the format: field:value, field:"quoted value", etc.
 *
 * @param query - The query string with potentially user-friendly field names
 * @returns The query with translated field names
 */
export function translateQueryFields(query: string): string {
  if (!query || typeof query !== 'string') {
    return query;
  }

  // Pattern to match field:value pairs
  const fieldValuePattern = /([a-zA-Z_][a-zA-Z0-9_]*):(\S+|"[^"]*")/g;

  return query.replace(fieldValuePattern, (_match, field, value) => {
    const translatedField = translateFieldName(field);
    return `${translatedField}:${value}`;
  });
}

/**
 * Check if a field name needs translation
 */
export function needsTranslation(field: string): boolean {
  return field.toLowerCase() in FIELD_MAPPINGS;
}

/**
 * Get the original user-friendly name for an API field (reverse lookup)
 */
export function getOriginalFieldName(apiField: string): string | null {
  for (const [userField, mappedField] of Object.entries(FIELD_MAPPINGS)) {
    if (mappedField === apiField) {
      return userField;
    }
  }
  return null;
}
