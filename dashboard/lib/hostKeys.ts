// dashboard/lib/hostKeys.ts
// Parsing and fingerprinting of SSH public host keys for out-of-band pinning.
import { createHash } from 'crypto';

const KEY_TYPES = new Set(['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa']);

export interface ParsedHostKey {
  type: string;
  key: string;
  fingerprint: string;
}

/**
 * Accepts "TYPE BASE64", a known_hosts line ("host TYPE BASE64"), or
 * ssh-keyscan output, and checks that the key blob really is of the named type.
 */
export function parseHostKey(input: string): ParsedHostKey {
  const line = input.split(/\r?\n/).map((l) => l.trim()).find((l) => l && !l.startsWith('#'));
  if (!line) throw new Error('No key found.');
  const parts = line.split(/\s+/);
  const idx = parts.findIndex((p) => KEY_TYPES.has(p));
  if (idx === -1 || !parts[idx + 1]) throw new Error(`Expected one of: ${Array.from(KEY_TYPES).join(', ')} followed by the base64 key.`);
  const type = parts[idx];
  const key = parts[idx + 1];
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(key)) throw new Error('Key is not valid base64.');

  const blob = Buffer.from(key, 'base64');
  if (blob.length < 4) throw new Error('Key is too short.');
  const len = blob.readUInt32BE(0);
  const embedded = blob.subarray(4, 4 + len).toString('ascii');
  if (embedded !== type) throw new Error(`Key data is for "${embedded || 'unknown'}", not "${type}".`);

  const fingerprint = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
  return { type, key, fingerprint };
}
