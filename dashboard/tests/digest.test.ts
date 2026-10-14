import { describe, it, expect } from 'vitest';
import { digestPdf, digestText, type DigestData } from '@/lib/digest';
import { computeCompliance } from '@/lib/compliance';

const data: DigestData = {
  orgName: 'Acme',
  generatedAt: '2026-10-12T08:00:00.000Z',
  devices: [{ hostname: 'R1', risk: 'HIGH', status: 'online' }, { hostname: 'R2', risk: 'LOW', status: 'unreachable' }],
  riskCounts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 1, UNASSESSED: 0 },
  compliance: computeCompliance([
    { deviceId: 'a', hostname: 'R1', vendor: 'cisco_ios', failingRuleIds: ['CIS-1.3', 'CIS-1.7'] },
    { deviceId: 'b', hostname: 'R2', vendor: 'cisco_ios', failingRuleIds: [] },
  ]),
  exploitedDevices: [{ hostname: 'R1', kevCount: 2 }],
  riskyChanges: [{ hostname: 'R1', severity: 'CRITICAL', when: '2026-10-10', summary: 'Telnet management enabled' }],
  pendingApprovals: 1,
  unreachable: 1,
};

describe('digest', () => {
  it('summarises the fleet in text', () => {
    const text = digestText(data);
    expect(text).toContain('Acme');
    expect(text).toContain('R1 (2)');
    expect(text).toMatch(/CIS-1\.3 .*: 1\/2 devices failing/);
  });

  it('renders a PDF on the server', () => {
    const pdf = Buffer.from(digestPdf(data), 'base64');
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
    expect(pdf.length).toBeGreaterThan(2000);
  });
});
