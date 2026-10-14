import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, createHash } from 'crypto';
import { parseHostKey } from '@/lib/hostKeys';

// Build a real OpenSSH ssh-ed25519 public key blob.
function ed25519Line(): { line: string; fp: string } {
  const { publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const blob = Buffer.concat([u32(11), Buffer.from('ssh-ed25519'), u32(32), raw]);
  return { line: `ssh-ed25519 ${blob.toString('base64')}`, fp: 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '') };
}

describe('parseHostKey', () => {
  it('parses a bare key and computes the OpenSSH fingerprint', () => {
    const { line, fp } = ed25519Line();
    expect(parseHostKey(line)).toMatchObject({ type: 'ssh-ed25519', fingerprint: fp });
  });

  it('accepts ssh-keyscan / known_hosts lines with comments', () => {
    const { line } = ed25519Line();
    expect(parseHostKey(`# 10.0.0.1:22 SSH-2.0-Cisco-1.25\n10.0.0.1 ${line}`).type).toBe('ssh-ed25519');
  });

  it('rejects a key whose data does not match the declared type', () => {
    const { line } = ed25519Line();
    expect(() => parseHostKey(line.replace('ssh-ed25519', 'ssh-rsa'))).toThrow(/not "ssh-rsa"/);
  });

  it('rejects garbage', () => {
    expect(() => parseHostKey('hello world')).toThrow();
    expect(() => parseHostKey('ssh-ed25519 !!!notbase64')).toThrow(/base64/);
  });
});
