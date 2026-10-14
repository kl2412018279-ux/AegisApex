// dashboard/lib/riskHistory.ts
import type { SupabaseClient } from '@supabase/supabase-js';

export interface RiskSample {
  deviceId: string;
  riskLevel: string;
  source: 'config' | 'firmware' | 'combined';
  findingsCount?: number;
  rulesEvaluated?: number;
  cveCount?: number;
  kevCount?: number;
}

export async function recordRisk(admin: SupabaseClient, sample: RiskSample): Promise<void> {
  const { error } = await admin.from('risk_history').insert({
    device_id: sample.deviceId,
    risk_level: sample.riskLevel,
    source: sample.source,
    findings_count: sample.findingsCount ?? null,
    rules_evaluated: sample.rulesEvaluated ?? null,
    cve_count: sample.cveCount ?? null,
    kev_count: sample.kevCount ?? null,
  });
  if (error) console.warn('[!] risk_history insert failed:', error.message);
}
