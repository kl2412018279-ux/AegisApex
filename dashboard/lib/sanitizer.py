// dashboard/lib/sanitizer.py

/**
 * Scrubs credentials, hashes, and private keys from network device CLI outputs.
 */
export function sanitizeConfig(rawConfig: string): string {
  if (!rawConfig) return '';

  let sanitized = rawConfig;

  const patterns: { name: string; regex: RegExp; replace: string }[] = [
    // Enable secret & password (Type 5, 7, 8, 9, or plain)
    {
      name: 'Enable Secrets',
      regex: /(enable\s+(?:secret|password)(?:\s+level\s+\d+)?\s+)(?:\d+\s+)?(\S+)/gi,
      replace: '$1[SCRUBBED_ENABLE_SECRET]',
    },
    // User credentials and secrets
    {
      name: 'User Passwords',
      regex: /(username\s+\S+\s+(?:secret|password)\s+)(?:\d+\s+)?(\S+)/gi,
      replace: '$1[SCRUBBED_USER_SECRET]',
    },
    // BGP neighbor secrets
    {
      name: 'BGP Passwords',
      regex: /(neighbor\s+\S+\s+password\s+)(?:\d+\s+)?(\S+)/gi,
      replace: '$1[SCRUBBED_BGP_PASSWORD]',
    },
    // SNMP community strings
    {
      name: 'SNMP Community Strings',
      regex: /(snmp-server\s+community\s+)(\S+)/gi,
      replace: '$1[SCRUBBED_SNMP_COMMUNITY]',
    },
    // RADIUS & TACACS shared keys
    {
      name: 'AAA Server Keys',
      regex: /((?:tacacs-server|radius-server|key-server)\s+key\s+(?:\d+\s+)?)\S+/gi,
      replace: '$1[SCRUBBED_AAA_KEY]',
    },
    // Wi-Fi Pre-Shared Keys (PSK)
    {
      name: 'Wi-Fi PSK',
      regex: /(pre-shared-key\s+(?:hex|ascii)\s+)(\S+)/gi,
      replace: '$1[SCRUBBED_PSK]',
    },
    // IPSec / ISAKMP pre-shared keys
    {
      name: 'IPSec Keys',
      regex: /(crypto\s+(?:isakmp|ikev2)\s+key\s+)(\S+)/gi,
      replace: '$1[SCRUBBED_IPSEC_KEY]',
    },
    // SSL / RSA Private Key blocks
    {
      name: 'Private Key Blocks',
      regex: /-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----/gi,
      replace: '[SCRUBBED_PRIVATE_KEY_BLOCK]',
    },
  ];

  for (const { regex, replace } of patterns) {
    sanitized = sanitized.replace(regex, replace);
  }

  return sanitized;
}