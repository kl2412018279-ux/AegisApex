// dashboard/lib/risk.ts
// Single source of truth for server-side risk levels. Used by the scan,
// firmware, and rule-engine code paths so they can't drift apart.

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export const RISK_RANKS: Record<RiskLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const RANK_TO_LEVEL: Record<number, RiskLevel> = { 4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW' };

/** Strict normalizer: unknown input maps to `fallback` (LOW by default). */
export function normalizeRiskLevel(val?: string | null, fallback: RiskLevel = 'LOW'): RiskLevel {
  const normalized = String(val || '').toUpperCase().trim();
  if (normalized in RISK_RANKS) return normalized as RiskLevel;
  if (normalized === 'CRIT') return 'CRITICAL';
  if (normalized === 'MED' || normalized === 'MODERATE') return 'MEDIUM';
  if (normalized === 'INFORMATIONAL' || normalized === 'INFO') return 'LOW';
  return fallback;
}

export function getHighestRiskLevel(...levels: RiskLevel[]): RiskLevel {
  let best: RiskLevel = 'LOW';
  for (const level of levels) {
    if ((RISK_RANKS[level] ?? 1) > RISK_RANKS[best]) best = level;
  }
  return best;
}

export function riskRank(level?: string | null): number {
  const normalized = String(level || '').toUpperCase();
  return normalized in RISK_RANKS ? RISK_RANKS[normalized as RiskLevel] : 0;
}

/**
 * Caps the AI's self-rated risk relative to the deterministic floor.
 * A LOW floor (no evidence at all) allows no margin; any other floor allows
 * the AI to raise the rating by at most one step.
 */
export function clampAiRiskToFloor(
  aiRisk: RiskLevel,
  floorRisk: RiskLevel
): { clamped: RiskLevel; wasClamped: boolean } {
  const margin = floorRisk === 'LOW' ? 0 : 1;
  const ceilingRank = Math.min(4, RISK_RANKS[floorRisk] + margin);
  if (RISK_RANKS[aiRisk] <= ceilingRank) return { clamped: aiRisk, wasClamped: false };
  return { clamped: RANK_TO_LEVEL[ceilingRank], wasClamped: true };
}

export function riskBadge(level: RiskLevel): string {
  return level === 'CRITICAL' ? '🔴 CRITICAL' : level === 'HIGH' ? '🟠 HIGH' : level === 'MEDIUM' ? '🟡 MEDIUM' : '🟢 LOW';
}

/** vulnerabilities.severity has a CHECK constraint on Title Case values. */
export function severityTitleCase(level: string): string {
  const map: Record<string, string> = {
    CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low',
    INFORMATIONAL: 'Informational', SAFE: 'Safe',
  };
  return map[(level || '').toUpperCase()] || 'Informational';
}
