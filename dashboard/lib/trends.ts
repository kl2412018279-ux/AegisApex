// dashboard/lib/trends.ts
// Daily fleet risk distribution and compliance score from risk_history.
export interface HistoryRow {
  device_id: string;
  risk_level: string;
  source: 'config' | 'firmware' | 'combined';
  findings_count: number | null;
  rules_evaluated: number | null;
  recorded_at: string;
}

export interface TrendPoint {
  date: string;
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  devicesTracked: number;
  /** % of applicable CIS rules passing, averaged over devices with a config scan. */
  compliancePct: number | null;
}

const LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
const day = (iso: string) => iso.slice(0, 10);

/**
 * Builds one point per day. Each device's latest value carries forward until
 * it changes, so a device scanned on Monday still counts on Friday.
 * `rows` may include history from before `since` to seed the carry-forward.
 */
export function buildTrend(rows: HistoryRow[], since: Date, until: Date = new Date()): TrendPoint[] {
  const sorted = [...rows].sort((a, b) => a.recorded_at.localeCompare(b.recorded_at));
  const risk = new Map<string, string>();
  const compliance = new Map<string, number>();
  const points: TrendPoint[] = [];
  let i = 0;

  for (let d = new Date(Date.UTC(since.getUTCFullYear(), since.getUTCMonth(), since.getUTCDate())); d <= until; d.setUTCDate(d.getUTCDate() + 1)) {
    const key = d.toISOString().slice(0, 10);
    while (i < sorted.length && day(sorted[i].recorded_at) <= key) {
      const r = sorted[i++];
      // "combined" is what the inventory shows; fall back to the others until one exists.
      if (r.source === 'combined' || !risk.has(r.device_id) || risk.get(`${r.device_id}:src`) !== 'combined') {
        risk.set(r.device_id, r.risk_level.toUpperCase());
        risk.set(`${r.device_id}:src`, r.source);
      }
      if (r.source === 'config' && r.rules_evaluated) {
        compliance.set(r.device_id, 1 - (r.findings_count ?? 0) / r.rules_evaluated);
      }
    }
    const point: TrendPoint = { date: key, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, devicesTracked: 0, compliancePct: null };
    for (const [k, level] of Array.from(risk.entries())) {
      if (k.endsWith(':src')) continue;
      point.devicesTracked++;
      if ((LEVELS as readonly string[]).includes(level)) point[level as (typeof LEVELS)[number]]++;
    }
    if (compliance.size) {
      const values = Array.from(compliance.values());
      point.compliancePct = Math.round((values.reduce((a, b) => a + b, 0) / values.length) * 1000) / 10;
    }
    points.push(point);
  }
  return points;
}
