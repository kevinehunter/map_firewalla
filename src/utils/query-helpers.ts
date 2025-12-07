/**
 * Query Helper Utilities
 *
 * Provides utilities for normalizing and preprocessing search queries
 * before they are sent to the Firewalla API.
 */

/**
 * MAC address regex pattern (XX:XX:XX:XX:XX:XX format)
 */
const MAC_ADDRESS_PATTERN = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

/**
 * Check if a value looks like a MAC address
 */
export function isMacAddress(value: string): boolean {
  return MAC_ADDRESS_PATTERN.test(value);
}

/**
 * Auto-quote a value if it contains special characters that need quoting.
 * This handles MAC addresses and other colon-containing values.
 *
 * @param value - The value to potentially quote
 * @returns The value, quoted if necessary
 */
export function quoteValueIfNeeded(value: string): string {
  // Already quoted
  if (value.startsWith('"') && value.endsWith('"')) {
    return value;
  }

  // MAC addresses need quoting due to colons
  if (isMacAddress(value)) {
    return `"${value}"`;
  }

  // Values with spaces need quoting
  if (value.includes(' ')) {
    return `"${value}"`;
  }

  return value;
}

/**
 * Normalize a query by auto-quoting MAC addresses and other special values.
 * This preprocesses the query before validation and API submission.
 *
 * @param query - The raw query string
 * @returns The normalized query with properly quoted values
 */
export function normalizeQuery(query: string): string {
  if (!query || typeof query !== 'string') {
    return query;
  }

  // Pattern to match field:value pairs, capturing the field and value
  // Handles both quoted and unquoted values
  const fieldValuePattern = /([a-zA-Z_][a-zA-Z0-9_.]*):("(?:[^"\\]|\\.)*"|[^\s()]+)/g;

  return query.replace(fieldValuePattern, (match, field, value) => {
    // Skip already quoted values
    if (value.startsWith('"')) {
      return match;
    }

    // Check if value looks like a MAC address (contains multiple colons)
    if (isMacAddress(value)) {
      return `${field}:"${value}"`;
    }

    return match;
  });
}

/**
 * Extract the field name from a field:value expression
 */
export function extractFieldName(expression: string): string | null {
  const match = expression.match(/^([a-zA-Z_][a-zA-Z0-9_.]*?):/);
  return match ? match[1] : null;
}

/**
 * Extract the value from a field:value expression
 */
export function extractFieldValue(expression: string): string | null {
  const match = expression.match(/^[a-zA-Z_][a-zA-Z0-9_.]*?:(.+)$/);
  if (!match) return null;

  let value = match[1];

  // Remove surrounding quotes if present
  if (value.startsWith('"') && value.endsWith('"')) {
    value = value.slice(1, -1);
  }

  return value;
}
