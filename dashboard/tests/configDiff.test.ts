import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import path from 'path';
import { computeDrift, classifyRiskyChanges, withContext } from '@/lib/configDiff';

const hardened = readFileSync(path.join(__dirname, 'fixtures', 'cisco_ios_hardened.txt'), 'utf8');

describe('computeDrift', () => {
  it('reports nothing for identical configs that differ only in noise', () => {
    const a = '! Last configuration change at 10:00:01 UTC Mon\n' + hardened;
    const b = '! Last configuration change at 11:22:33 UTC Tue\nBuilding configuration...\n' + hardened;
    const r = computeDrift(a, b, 'cisco_ios');
    expect(r.addedLines).toBe(0);
    expect(r.removedLines).toBe(0);
    expect(r.severity).toBeNull();
  });

  it('flags a weakened VTY line and the CIS regression it causes', () => {
    const weakened = hardened.replace(/line vty 5 15\n access-class MGMT-ACL in\n exec-timeout 10 0\n transport input ssh/, 'line vty 5 15\n exec-timeout 10 0\n transport input telnet ssh');
    const r = computeDrift(hardened, weakened, 'cisco_ios');
    expect(r.riskyChanges.map((c) => c.title)).toEqual(expect.arrayContaining(['Telnet management enabled', 'Management access ACL removed']));
    expect(r.newFindings.some((f) => f.startsWith('CIS-1.3'))).toBe(true);
    expect(r.newFindings.some((f) => f.startsWith('CIS-1.10'))).toBe(true);
    expect(r.severity).toBe('CRITICAL');
  });

  it('reports resolved findings when a change fixes something', () => {
    const before = hardened.replace('no ip http server\n', 'ip http server\n');
    const r = computeDrift(before, hardened, 'cisco_ios');
    expect(r.resolvedFindings).toContain('CIS-1.4');
  });

  it('redacts secrets in the diff output', () => {
    const r = computeDrift('hostname R1\n', 'hostname R1\nsnmp-server community s3cr3t RW\n', 'cisco_ios');
    expect(JSON.stringify(r)).not.toContain('s3cr3t');
    expect(r.riskyChanges[0]).toMatchObject({ severity: 'CRITICAL', title: 'SNMP read-write community added' });
  });
});

describe('classifyRiskyChanges', () => {
  it('detects permissive ACLs and new admin accounts', () => {
    const r = classifyRiskyChanges([' permit ip any any', 'username temp privilege 15 secret 9 $9$x'], []);
    expect(r.map((c) => c.title)).toEqual(['Permissive "permit any" ACL entry added', 'New or changed privileged local account']);
  });
});

describe('withContext', () => {
  it('collapses long unchanged runs', () => {
    const lines = Array.from({ length: 20 }, (_, i) => ({ type: 'same' as const, text: `l${i}` }));
    lines[10] = { type: 'add' as const, text: 'new' } as never;
    const out = withContext(lines, 2);
    expect(out[0]).toEqual({ type: 'gap', count: 8 });
    expect(out.filter((l) => l.type !== 'gap')).toHaveLength(5);
  });
});
