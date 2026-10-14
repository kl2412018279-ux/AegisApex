import { describe, it, expect } from 'vitest';
import { computeCompliance } from '@/lib/compliance';
import { buildTrend } from '@/lib/trends';
import { applicableRuleIds, resolveRuleId } from '@/lib/cisBenchmarks';

describe('computeCompliance', () => {
  const all = applicableRuleIds('cisco_ios');

  it('scores a fully compliant fleet at 100%', () => {
    const r = computeCompliance([{ deviceId: 'a', hostname: 'A', vendor: 'cisco_ios', failingRuleIds: [] }]);
    expect(r.overallScorePct).toBe(100);
    expect(r.frameworks.every((f) => f.scorePct === 100 || f.scorePct === null)).toBe(true);
  });

  it('attributes framework control failures to the right devices', () => {
    const r = computeCompliance([
      { deviceId: 'a', hostname: 'A', vendor: 'cisco_ios', failingRuleIds: ['CIS-1.3'] },
      { deviceId: 'b', hostname: 'B', vendor: 'cisco_ios', failingRuleIds: [] },
      { deviceId: 'c', hostname: 'C', vendor: 'cisco_ios', failingRuleIds: null },
    ]);
    expect(r.assessedDevices).toBe(2);
    expect(r.unassessedDevices).toBe(1);
    const pci = r.frameworks.find((f) => f.framework === 'pciDss4')!;
    expect(pci.controls.find((c) => c.control === '2.2.7')!.failingDevices).toEqual(['A']);
    expect(r.overallScorePct).toBeCloseTo(((all.length * 2 - 1) / (all.length * 2)) * 100, 0);
    expect(r.ruleFailures[0]).toMatchObject({ ruleId: 'CIS-1.3', failing: 1, applicable: 2 });
  });

  it('resolves legacy findings stored by title', () => {
    expect(resolveRuleId(null, 'Ensure HTTP Management Server is Disabled')).toBe('CIS-1.4');
    expect(resolveRuleId('GENERIC-CIS-4', 'Something custom')).toBeNull();
  });
});

describe('buildTrend', () => {
  it('carries each device forward and prefers the combined rating', () => {
    const points = buildTrend(
      [
        { device_id: 'a', risk_level: 'HIGH', source: 'config', findings_count: 2, rules_evaluated: 10, recorded_at: '2026-10-01T10:00:00Z' },
        { device_id: 'a', risk_level: 'CRITICAL', source: 'combined', findings_count: null, rules_evaluated: null, recorded_at: '2026-10-01T11:00:00Z' },
        { device_id: 'a', risk_level: 'LOW', source: 'firmware', findings_count: null, rules_evaluated: null, recorded_at: '2026-10-02T09:00:00Z' },
        { device_id: 'b', risk_level: 'LOW', source: 'combined', findings_count: null, rules_evaluated: null, recorded_at: '2026-10-03T09:00:00Z' },
      ],
      new Date('2026-10-01T00:00:00Z'),
      new Date('2026-10-03T23:00:00Z')
    );
    expect(points.map((p) => [p.date, p.CRITICAL, p.LOW, p.devicesTracked])).toEqual([
      ['2026-10-01', 1, 0, 1],
      ['2026-10-02', 1, 0, 1],
      ['2026-10-03', 1, 1, 2],
    ]);
    expect(points[0].compliancePct).toBe(80);
  });
});
