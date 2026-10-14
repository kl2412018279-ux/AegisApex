import { describe, it, expect } from 'vitest';
import { clampAiRiskToFloor, getHighestRiskLevel, normalizeRiskLevel } from '@/lib/risk';

describe('risk helpers', () => {
  it('normalizes aliases and unknowns', () => {
    expect(normalizeRiskLevel('crit')).toBe('CRITICAL');
    expect(normalizeRiskLevel('info')).toBe('LOW');
    expect(normalizeRiskLevel('nonsense')).toBe('LOW');
    expect(normalizeRiskLevel('nonsense', 'MEDIUM')).toBe('MEDIUM');
  });

  it('picks the highest level', () => {
    expect(getHighestRiskLevel('LOW', 'HIGH', 'MEDIUM')).toBe('HIGH');
  });

  it('gives the AI no margin above a LOW floor', () => {
    expect(clampAiRiskToFloor('MEDIUM', 'LOW')).toEqual({ clamped: 'LOW', wasClamped: true });
  });

  it('allows one step above a non-LOW floor', () => {
    expect(clampAiRiskToFloor('HIGH', 'MEDIUM')).toEqual({ clamped: 'HIGH', wasClamped: false });
    expect(clampAiRiskToFloor('CRITICAL', 'MEDIUM')).toEqual({ clamped: 'HIGH', wasClamped: true });
  });
});
