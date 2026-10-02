// riskHelpers.ts
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNASSESSED';

export const RISK_WEIGHTS: Record<RiskLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNASSESSED: 0,
};

/**
 * Normalizes arbitrary threat strings to a canonical RiskLevel type.
 * Prevents false positives from strings like "BYPASS" or "PASSWORD".
 */
export function normalizeRiskLevel(r?: string): RiskLevel {
  if (!r) return 'UNASSESSED';
  const upper = r.toUpperCase().trim();

  if (upper.includes('CRIT')) return 'CRITICAL';
  if (upper.includes('HIGH')) return 'HIGH';
  if (upper.includes('MED') || upper.includes('MODERAT') || upper.includes('WARN')) return 'MEDIUM';
  if (upper.includes('LOW') || upper.includes('SAFE') || upper === 'PASS') return 'LOW';

  return 'UNASSESSED';
}

/**
 * Evaluates any number of risk levels and returns the highest authoritative threat level.
 * Example: getHighestRisk(dev.risk_level, scan.risk_level, cachedRisk)
 */
export function getHighestRisk(...risks: (string | undefined)[]): RiskLevel {
  let highestRisk: RiskLevel = 'UNASSESSED';
  let maxWeight = 0;

  for (const risk of risks) {
    const normalized = normalizeRiskLevel(risk);
    const weight = RISK_WEIGHTS[normalized] || 0;

    if (weight > maxWeight) {
      maxWeight = weight;
      highestRisk = normalized;
    }
  }

  return highestRisk;
}

export function getRiskColor(level?: string, isDark = false) {
  const normalizedLevel = normalizeRiskLevel(level);

  switch (normalizedLevel) {
    case 'CRITICAL':
      return {
        badge: isDark
          ? 'bg-rose-500/15 text-rose-300 border-rose-500/30 font-bold'
          : 'bg-rose-100 text-rose-800 border-rose-300 font-bold',
        bar: 'bg-rose-500',
        text: isDark ? 'text-rose-400' : 'text-rose-700',
        border: isDark ? 'border-rose-800' : 'border-rose-200',
        accent: 'border-l-rose-500',
      };

    case 'HIGH':
      return {
        badge: isDark
          ? 'bg-orange-500/15 text-orange-300 border-orange-500/30 font-bold'
          : 'bg-orange-100 text-orange-800 border-orange-300 font-bold',
        bar: 'bg-orange-500',
        text: isDark ? 'text-orange-400' : 'text-orange-700',
        border: isDark ? 'border-orange-800' : 'border-orange-200',
        accent: 'border-l-orange-500',
      };

    case 'MEDIUM':
      return {
        badge: isDark
          ? 'bg-amber-500/15 text-amber-300 border-amber-500/30 font-bold'
          : 'bg-amber-100 text-amber-800 border-amber-300 font-bold',
        bar: 'bg-amber-500',
        text: isDark ? 'text-amber-400' : 'text-amber-700',
        border: isDark ? 'border-amber-800' : 'border-amber-200',
        accent: 'border-l-amber-500',
      };

    case 'LOW':
      return {
        badge: isDark
          ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-bold'
          : 'bg-emerald-100 text-emerald-800 border-emerald-300 font-bold',
        bar: 'bg-emerald-500',
        text: isDark ? 'text-emerald-400' : 'text-emerald-700',
        border: isDark ? 'border-emerald-800' : 'border-emerald-200',
        accent: 'border-l-emerald-500',
      };

    default:
      return {
        badge: isDark
          ? 'bg-slate-800 text-slate-300 border-slate-700 font-bold'
          : 'bg-slate-100 text-slate-700 border-slate-300 font-bold',
        bar: 'bg-slate-500',
        text: isDark ? 'text-slate-400' : 'text-slate-700',
        border: isDark ? 'border-slate-800' : 'border-slate-200',
        accent: 'border-l-slate-500',
      };
  }
}