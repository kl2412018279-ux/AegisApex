import { describe, it, expect } from 'vitest';
import { tokenizeConfig, detokenizeConfig, sanitizeConfig } from '@/lib/sanitizer';

// One sample line per redaction pattern in shared/redaction-patterns.json.
// If a pattern regresses, the secret will leak into LLM prompts.
const CASES: Array<[string, string, string]> = [
  ['cisco_secret_type5_8_9', 'enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0', '$1$mERr$hx5rVt7rPNoS4wqbXKX7m0'],
  ['cisco_type7_passwords', 'username admin password 7 0822455D0A16', '0822455D0A16'],
  ['aruba_cx_ciphertext_plaintext', 'user admin group administrators password ciphertext AQBapXYZsecret==', 'AQBapXYZsecret=='],
  ['unix_aruba_crypt_hash', 'root-hash $6$rounds=5000$saltsalt$abcdefghijklmnop', '$6$rounds=5000$saltsalt$abcdefghijklmnop'],
  ['juniper_9_encrypted', 'encrypted-password "$9$Ab3CdeFgHiJk"', '$9$Ab3CdeFgHiJk'],
  ['fortinet_enc_passwords', 'set password ENC SH2kQ3ZmRsT1', 'SH2kQ3ZmRsT1'],
  ['huawei_hp_cipher_simple', 'local-user admin password cipher %^%#Xyz123%^%#', '%^%#Xyz123%^%#'],
  ['paloalto_phash', 'phash $1$abcdefgh$ijklmnopqrstuv', '$1$abcdefgh$ijklmnopqrstuv'],
  ['mikrotik_quoted_secrets', '/user add name=admin password="MikroPass1"', 'MikroPass1'],
  ['snmp_community_strings', 'snmp-server community s3cr3tRW RW', 's3cr3tRW'],
  ['radius_tacacs_keys', 'tacacs-server host 10.0.0.5 key 0 TacKey99', 'TacKey99'],
  ['ipsec_ike_psk', 'crypto isakmp key IkeSecret1 address 0.0.0.0', 'IkeSecret1'],
  ['ntp_authentication_keys', 'ntp authentication-key 1 md5 0822455D0A16 7', '0822455D0A16'],
  ['routing_protocol_keys', ' ip ospf message-digest-key 1 md5 OspfKey9', 'OspfKey9'],
  ['routing_protocol_keys (junos)', 'set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key "$9$abc"', '$9$abc'],
  ['ssh_private_keys', '-----BEGIN RSA PRIVATE KEY-----\nMIIEsecretbody\n-----END RSA PRIVATE KEY-----', 'MIIEsecretbody'],
  ['generic_credential_fallback', 'set system login user ops authentication plaintext-password Plain123\nauth-password VyosSecret', 'VyosSecret'],
];

describe('sanitizeConfig', () => {
  it.each(CASES)('%s removes the secret', (_id, line, secret) => {
    const out = sanitizeConfig(line);
    expect(out).not.toContain(secret);
    expect(out).toContain('[REDACTED]');
  });

  it('keeps non-secret config intact', () => {
    const cfg = 'hostname R1\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n';
    expect(sanitizeConfig(cfg)).toBe(cfg);
  });
});

describe('tokenize / detokenize', () => {
  it('round-trips a config exactly', () => {
    const cfg = CASES.map(([, line]) => line).join('\n');
    const { sanitizedConfig, tokens } = tokenizeConfig(cfg);
    expect(Object.keys(tokens).length).toBeGreaterThan(5);
    expect(detokenizeConfig(sanitizedConfig, tokens)).toBe(cfg);
  });

  it('round-trips unquoted Junos secrets without adding quotes', () => {
    const cfg = 'set system root-authentication encrypted-password $9$Ab3CdeFgHiJk';
    const { sanitizedConfig, tokens } = tokenizeConfig(cfg);
    expect(sanitizedConfig).not.toContain('$9$Ab3CdeFgHiJk');
    expect(detokenizeConfig(sanitizedConfig, tokens)).toBe(cfg);
  });

  it('reuses one token for a repeated secret', () => {
    const { tokens } = tokenizeConfig('username a password 7 ABCDEF\nusername b password 7 ABCDEF');
    expect(Object.values(tokens).filter((v) => v === 'ABCDEF')).toHaveLength(1);
  });
});
