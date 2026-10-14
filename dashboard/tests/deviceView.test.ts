import { describe, it, expect } from 'vitest';
import { publicDevice } from '@/lib/deviceView';

describe('publicDevice', () => {
  it('drops credential columns and keeps everything else', () => {
    const row = {
      id: '1', hostname: 'R1', device_type: 'cisco_ios', ssh_user: 'admin',
      ssh_pass: 'x', ssh_password: 'x', enable_pass: 'x', enable_secret: 'x', password: 'x', api_token: 'x',
      ssh_host_key: 'AAAA', ssh_host_key_fingerprint: 'SHA256:abc', ssh_host_key_type: 'ssh-ed25519',
      last_config: 'hostname R1',
    };
    const out = publicDevice(row);
    expect(Object.keys(out).sort()).toEqual(
      ['device_type', 'hostname', 'id', 'last_config', 'ssh_host_key_fingerprint', 'ssh_host_key_type', 'ssh_user'].sort()
    );
  });
});
