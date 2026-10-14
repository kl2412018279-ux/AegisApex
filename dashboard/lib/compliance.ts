// dashboard/lib/compliance.ts
// Fleet compliance posture per framework, from each device's latest scan.
import type { SupabaseClient } from '@supabase/supabase-js';
import { CIS_BENCHMARK_MATRIX, FRAMEWORK_LABELS, RULE_FRAMEWORKS, applicableRuleIds, resolveRuleId, type FrameworkMapping } from './cisBenchmarks';

export interface DeviceFindings {
  deviceId: string;
  hostname: string;
  vendor: string;
  /** null = never scanned */
  failingRuleIds: string[] | null;
}

export interface ControlStatus {
  control: string;
  rules: string[];
  failingDevices: string[];
  assessedDevices: number;
}

export interface FrameworkPosture {
  framework: keyof FrameworkMapping;
  label: string;
  scorePct: number | null;
  controls: ControlStatus[];
}

export interface CompliancePosture {
  assessedDevices: number;
  unassessedDevices: number;
  overallScorePct: number | null;
  frameworks: FrameworkPosture[];
  ruleFailures: Array<{ ruleId: string; title: string; failing: number; applicable: number }>;
}

const pct = (pass: number, total: number) => (total ? Math.round((pass / total) * 1000) / 10 : null);

export function computeCompliance(devices: DeviceFindings[]): CompliancePosture {
  const assessed = devices.filter((d) => d.failingRuleIds !== null);
  const applicable = new Map(assessed.map((d) => [d.deviceId, new Set(applicableRuleIds(d.vendor))]));
  const failing = new Map(assessed.map((d) => [d.deviceId, new Set(d.failingRuleIds!)]));

  let pass = 0;
  let total = 0;
  const ruleFailures = CIS_BENCHMARK_MATRIX.map((rule) => {
    let ruleApplicable = 0;
    let ruleFailing = 0;
    for (const d of assessed) {
      if (!applicable.get(d.deviceId)!.has(rule.ruleId)) continue;
      ruleApplicable++;
      if (failing.get(d.deviceId)!.has(rule.ruleId)) ruleFailing++;
    }
    pass += ruleApplicable - ruleFailing;
    total += ruleApplicable;
    return { ruleId: rule.ruleId, title: rule.title, failing: ruleFailing, applicable: ruleApplicable };
  }).filter((r) => r.applicable > 0);

  const frameworks = (Object.keys(FRAMEWORK_LABELS) as Array<keyof FrameworkMapping>).map((fw) => {
    const byControl = new Map<string, string[]>();
    for (const [ruleId, mapping] of Object.entries(RULE_FRAMEWORKS)) {
      for (const control of mapping[fw]) byControl.set(control, [...(byControl.get(control) || []), ruleId]);
    }
    let fwPass = 0;
    let fwTotal = 0;
    const controls: ControlStatus[] = Array.from(byControl.entries())
      .map(([control, rules]) => {
        const relevant = assessed.filter((d) => rules.some((r) => applicable.get(d.deviceId)!.has(r)));
        const failingDevices = relevant.filter((d) => rules.some((r) => failing.get(d.deviceId)!.has(r))).map((d) => d.hostname);
        fwPass += relevant.length - failingDevices.length;
        fwTotal += relevant.length;
        return { control, rules, failingDevices, assessedDevices: relevant.length };
      })
      .sort((a, b) => b.failingDevices.length - a.failingDevices.length || a.control.localeCompare(b.control, undefined, { numeric: true }));
    return { framework: fw, label: FRAMEWORK_LABELS[fw], scorePct: pct(fwPass, fwTotal), controls };
  });

  return {
    assessedDevices: assessed.length,
    unassessedDevices: devices.length - assessed.length,
    overallScorePct: pct(pass, total),
    frameworks,
    ruleFailures: ruleFailures.sort((a, b) => b.failing - a.failing),
  };
}

/** Failing rule ids from each device's latest completed scan. */
export async function loadDeviceFindings(admin: SupabaseClient, devices: Array<{ id: string; hostname: string; vendor: string | null; netmiko_type: string | null }>): Promise<DeviceFindings[]> {
  const ids = devices.map((d) => d.id);
  if (!ids.length) return [];
  const { data: scans } = await admin
    .from('scans')
    .select('id, device_id, created_at, rules_evaluated, status')
    .in('device_id', ids)
    .eq('status', 'completed')
    .order('created_at', { ascending: false })
    .limit(ids.length * 10);
  const latest = new Map<string, string>();
  for (const s of scans || []) if (!latest.has(s.device_id)) latest.set(s.device_id, s.id);

  const scanIds = Array.from(latest.values());
  const { data: vulns } = scanIds.length
    ? await admin.from('vulnerabilities').select('scan_id, rule_id, title').in('scan_id', scanIds)
    : { data: [] as Array<{ scan_id: string; rule_id: string | null; title: string | null }> };

  return devices.map((d) => {
    const scanId = latest.get(d.id);
    const failing = scanId
      ? (vulns || []).filter((v) => v.scan_id === scanId).map((v) => resolveRuleId(v.rule_id, v.title)).filter((x): x is string => !!x)
      : null;
    return { deviceId: d.id, hostname: d.hostname, vendor: d.netmiko_type || d.vendor || 'generic', failingRuleIds: failing };
  });
}
