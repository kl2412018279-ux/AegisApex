import { describe, it, expect, beforeEach } from 'vitest';
import { generateSmartRollback } from '@/lib/rollback';
import { checkRateLimit, resetRateLimits } from '@/lib/rateLimit';
import { ScanBody, RiskBody, AlertChannelBody } from '@/lib/validation';

describe('generateSmartRollback', () => {
  it('inverts IOS commands and keeps context and exit lines', () => {
    expect(generateSmartRollback('line vty 0 4\n transport input ssh\n no exec-timeout\nexit', 'cisco_ios'))
      .toEqual(['line vty 0 4', 'no transport input ssh', 'exec-timeout', 'exit']);
  });
  it('uses set/delete for Junos', () => {
    expect(generateSmartRollback('set system services ssh', 'juniper_junos')).toEqual(['delete system services ssh']);
  });
  it('uses undo for Huawei', () => {
    expect(generateSmartRollback('telnet server enable', 'huawei')).toEqual(['undo telnet server enable']);
  });
  it('refuses to invert destructive commands', () => {
    expect(generateSmartRollback('reload', 'cisco_ios')[0]).toMatch(/^! Cannot be reversed/);
  });
});

describe('checkRateLimit', () => {
  beforeEach(() => resetRateLimits());
  it('allows up to the limit inside the window, then blocks', () => {
    for (let i = 0; i < 3; i++) expect(checkRateLimit('k', 3, 1000, 0).ok).toBe(true);
    const blocked = checkRateLimit('k', 3, 1000, 100);
    expect(blocked.ok).toBe(false);
    expect(blocked.retryAfterSec).toBe(1);
    expect(checkRateLimit('k', 3, 1000, 1001).ok).toBe(true);
  });
});

describe('validation', () => {
  const id = '3fa85f64-5717-4562-b3fc-2c963f66afa6';
  it('accepts snake_case aliases', () => {
    expect(ScanBody.parse({ device_id: id, raw_config: 'x' })).toMatchObject({ deviceId: id, rawConfig: 'x' });
  });
  it('rejects non-UUID device ids', () => {
    expect(() => ScanBody.parse({ deviceId: '1; drop table devices' })).toThrow();
  });
  it('normalizes risk levels', () => {
    expect(RiskBody.parse({ deviceId: id, riskLevel: 'high' }).riskLevel).toBe('HIGH');
    expect(() => RiskBody.parse({ deviceId: id, riskLevel: 'SEVERE' })).toThrow();
  });
  it('requires https webhooks and valid emails', () => {
    expect(() => AlertChannelBody.parse({ orgId: id, name: 'x', kind: 'slack', target: 'http://insecure' })).toThrow();
    expect(AlertChannelBody.parse({ orgId: id, name: 'x', kind: 'email', target: 'ops@example.com' }).minSeverity).toBe('HIGH');
  });
});
