import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import path from 'path';
import { evaluateConfigDeterministically, detectVendor, CIS_BENCHMARK_MATRIX, RULE_FRAMEWORKS } from '@/lib/cisBenchmarks';

const fixture = (name: string) => readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
const ids = (cfg: string, vendor: string) => evaluateConfigDeterministically(cfg, vendor).findings.map((f) => f.ruleId).sort();

describe('CIS rule matrix', () => {
  it('maps every rule to compliance frameworks', () => {
    for (const rule of CIS_BENCHMARK_MATRIX) {
      expect(RULE_FRAMEWORKS[rule.ruleId], rule.ruleId).toBeDefined();
      expect(rule.cisControl).toMatch(/^CIS Controls v8 /);
    }
  });

  it('has unique rule ids', () => {
    const all = CIS_BENCHMARK_MATRIX.map((r) => r.ruleId);
    expect(new Set(all).size).toBe(all.length);
  });
});

describe('detectVendor', () => {
  it.each([
    ['cisco_xe', 'cisco_ios'],
    ['cisco_nxos', 'cisco_nxos'],
    ['cisco_xr', 'cisco_xr'],
    ['juniper_junos', 'juniper'],
    ['arista_eos', 'arista'],
    ['paloalto_panos', 'paloalto'],
    ['hp_comware', 'aruba_hpe'],
    ['f5_tmsh', 'f5_tmsh'],
    ['extreme_exos', 'extreme_exos'],
    ['mikrotik_routeros', 'mikrotik'],
    ['', 'generic'],
  ])('%s -> %s', (input, expected) => {
    expect(detectVendor(input)).toBe(expected);
  });
});

describe('Cisco IOS evaluation', () => {
  it('passes a hardened config cleanly', () => {
    const result = evaluateConfigDeterministically(fixture('cisco_ios_hardened.txt'), 'cisco_ios');
    expect(result.findings.map((f) => `${f.ruleId}: ${f.evidence}`)).toEqual([]);
    expect(result.riskLevel).toBe('LOW');
    expect(result.rulesEvaluated).toBeGreaterThanOrEqual(17);
  });

  it('flags every weakness in a weak config', () => {
    const found = ids(fixture('cisco_ios_weak.txt'), 'cisco_ios');
    for (const rule of ['CIS-1.1', 'CIS-1.2', 'CIS-1.3', 'CIS-1.4', 'CIS-1.6', 'CIS-1.7', 'CIS-1.8', 'CIS-1.9',
      'CIS-1.10', 'CIS-1.12', 'CIS-1.13', 'CIS-1.14', 'CIS-1.15', 'CIS-1.16', 'CIS-1.17', 'CIS-1.18', 'CIS-1.19']) {
      expect(found, rule).toContain(rule);
    }
    expect(found).not.toContain('CIS-1.11'); // NTP server is configured
  });

  it('scopes VTY checks to each line block', () => {
    const finding = evaluateConfigDeterministically(fixture('cisco_ios_weak.txt'), 'cisco_ios')
      .findings.find((f) => f.ruleId === 'CIS-1.10');
    expect(finding?.evidence).toContain('line vty 5 15');
    expect(finding?.evidence).not.toContain('line vty 0 4');
  });

  it('redacts secrets in evidence strings', () => {
    const findings = evaluateConfigDeterministically(fixture('cisco_ios_weak.txt'), 'cisco_ios').findings;
    const all = findings.map((f) => f.evidence || '').join('\n');
    expect(all).not.toContain('0822455D0A16');
    expect(all).not.toContain('s3cr3tRW');
    expect(all).not.toContain('cisco123');
  });

  it('lists the unused interfaces it found', () => {
    const f = evaluateConfigDeterministically(fixture('cisco_ios_weak.txt'), 'cisco_ios').findings.find((x) => x.ruleId === 'CIS-1.18');
    expect(f?.evidence).toContain('GigabitEthernet0/2');
    expect(f?.evidence).toContain('GigabitEthernet0/3');
    expect(f?.evidence).not.toContain('GigabitEthernet0/1');
  });

  it('attaches framework mappings to findings', () => {
    const f = evaluateConfigDeterministically(fixture('cisco_ios_weak.txt'), 'cisco_ios').findings.find((x) => x.ruleId === 'CIS-1.3');
    expect(f?.frameworks?.pciDss4).toContain('2.2.7');
  });

  it('returns no findings for an empty config', () => {
    expect(evaluateConfigDeterministically('!\n!\n', 'cisco_ios')).toEqual({ riskLevel: 'LOW', findings: [], rulesEvaluated: 0 });
  });
});

describe('platform-specific behaviour', () => {
  it('does not flag NX-OS for missing "transport input ssh" (NX-OS has no such command)', () => {
    const cfg = 'feature ssh\nusername admin password 5 $5$abc role network-admin\nline vty\n  exec-timeout 10\n';
    expect(ids(cfg, 'cisco_nxos')).not.toContain('CIS-1.3');
    expect(ids(cfg + 'feature telnet\n', 'cisco_nxos')).toContain('CIS-1.3');
  });

  it('flags Juniper telnet and default SNMP community', () => {
    const cfg = 'set system services telnet\nset system services ssh\nset snmp community public authorization read-only\n';
    const found = ids(cfg, 'juniper_junos');
    expect(found).toContain('CIS-1.3');
    expect(found).toContain('CIS-1.7');
    expect(found).toContain('CIS-1.13');
  });

  it('does not mistake a Junos BGP community for SNMP', () => {
    const cfg = 'policy-options {\n    community CUST members 65000:100;\n}\nsystem {\n    services {\n        ssh;\n    }\n}\n';
    expect(ids(cfg, 'juniper_junos')).not.toContain('CIS-1.13');
  });

  it('does not apply Cisco-only rules to FortiOS', () => {
    const found = ids('config system global\n set admintimeout 5\nend\n', 'fortinet');
    expect(found).not.toContain('CIS-1.14');
    expect(found).not.toContain('CIS-1.18');
  });

  it('flags FortiOS telnet in allowaccess', () => {
    const cfg = 'config system interface\n edit "port1"\n  set allowaccess ping https ssh telnet\n next\nend\n';
    expect(ids(cfg, 'fortinet')).toContain('CIS-1.3');
  });
});
