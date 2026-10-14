// dashboard/lib/digest.ts
// Weekly fleet security digest: PDF for email channels, text for the rest.
import type { SupabaseClient } from '@supabase/supabase-js';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { computeCompliance, loadDeviceFindings, type CompliancePosture } from './compliance';
import { channelWants, envChannels, sendToChannel, type AlertChannel } from './alerts';

export interface DigestData {
  orgName: string;
  generatedAt: string;
  devices: Array<{ hostname: string; risk: string; status: string }>;
  riskCounts: Record<string, number>;
  compliance: CompliancePosture;
  exploitedDevices: Array<{ hostname: string; kevCount: number }>;
  riskyChanges: Array<{ hostname: string; severity: string; when: string; summary: string }>;
  pendingApprovals: number;
  unreachable: number;
}

export async function gatherDigest(admin: SupabaseClient, orgId: string, now = new Date()): Promise<DigestData> {
  const weekAgo = new Date(now.getTime() - 7 * 86_400_000).toISOString();
  const [{ data: org }, { data: devices }] = await Promise.all([
    admin.from('organizations').select('name').eq('id', orgId).maybeSingle(),
    admin.from('devices').select('id, hostname, vendor, netmiko_type, risk_level, connection_status').eq('org_id', orgId),
  ]);
  const list = devices || [];
  const ids = list.map((d) => d.id);
  const name = (id: string) => list.find((d) => d.id === id)?.hostname || id;

  const [{ data: firmware }, { data: changes }, { count: pending }] = ids.length
    ? await Promise.all([
        admin.from('risk_history').select('device_id, kev_count, recorded_at').in('device_id', ids).eq('source', 'firmware').order('recorded_at', { ascending: false }).limit(ids.length * 5),
        admin.from('config_changes').select('device_id, severity, risky_changes, created_at').in('device_id', ids).gte('created_at', weekAgo).in('severity', ['HIGH', 'CRITICAL']).order('created_at', { ascending: false }).limit(50),
        admin.from('remediation_requests').select('id', { count: 'exact', head: true }).in('device_id', ids).eq('status', 'pending_approval'),
      ])
    : [{ data: [] }, { data: [] }, { count: 0 }];

  const latestKev = new Map<string, number>();
  for (const r of firmware || []) if (!latestKev.has(r.device_id)) latestKev.set(r.device_id, r.kev_count ?? 0);

  const riskCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNASSESSED: 0 };
  for (const d of list) {
    const r = String(d.risk_level || 'UNASSESSED').toUpperCase();
    riskCounts[r in riskCounts ? r : 'UNASSESSED']++;
  }

  return {
    orgName: org?.name || 'Organization',
    generatedAt: now.toISOString(),
    devices: list.map((d) => ({ hostname: d.hostname, risk: String(d.risk_level || 'UNASSESSED').toUpperCase(), status: d.connection_status || 'unknown' })),
    riskCounts,
    compliance: computeCompliance(await loadDeviceFindings(admin, list)),
    exploitedDevices: Array.from(latestKev.entries()).filter(([, n]) => n > 0).map(([id, n]) => ({ hostname: name(id), kevCount: n })),
    riskyChanges: (changes || []).map((c) => ({
      hostname: name(c.device_id),
      severity: c.severity,
      when: c.created_at.slice(0, 10),
      summary: ((c.risky_changes || []) as Array<{ title: string }>).map((x) => x.title).slice(0, 3).join('; '),
    })),
    pendingApprovals: pending ?? 0,
    unreachable: list.filter((d) => d.connection_status === 'unreachable').length,
  };
}

export function digestText(d: DigestData): string {
  const fw = d.compliance.frameworks.map((f) => `${f.label}: ${f.scorePct ?? '—'}%`).join(' · ');
  return [
    `*${d.orgName} — weekly security digest*`,
    `Devices: ${d.devices.length} (🔴 ${d.riskCounts.CRITICAL} · 🟠 ${d.riskCounts.HIGH} · 🟡 ${d.riskCounts.MEDIUM} · 🟢 ${d.riskCounts.LOW} · unassessed ${d.riskCounts.UNASSESSED})`,
    `CIS compliance: ${d.compliance.overallScorePct ?? '—'}% (${fw})`,
    d.exploitedDevices.length ? `🚨 Running actively exploited firmware: ${d.exploitedDevices.map((x) => `${x.hostname} (${x.kevCount})`).join(', ')}` : '✅ No device runs firmware with known-exploited CVEs.',
    `High-risk config changes this week: ${d.riskyChanges.length}`,
    `Changes awaiting approval: ${d.pendingApprovals} · Unreachable devices: ${d.unreachable}`,
    d.compliance.ruleFailures.filter((r) => r.failing).slice(0, 5).map((r) => `• ${r.ruleId} ${r.title}: ${r.failing}/${r.applicable} devices failing`).join('\n'),
  ].filter(Boolean).join('\n');
}

export function digestPdf(d: DigestData): string {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  doc.setFontSize(16);
  doc.text(`${d.orgName} — Weekly Security Digest`, 14, 18);
  doc.setFontSize(9);
  doc.text(`Generated ${d.generatedAt.replace('T', ' ').slice(0, 16)} UTC by AegisApex`, 14, 24);

  autoTable(doc, {
    startY: 30,
    head: [['Metric', 'Value']],
    body: [
      ['Devices', String(d.devices.length)],
      ['Critical / High / Medium / Low', `${d.riskCounts.CRITICAL} / ${d.riskCounts.HIGH} / ${d.riskCounts.MEDIUM} / ${d.riskCounts.LOW}`],
      ['Unassessed', String(d.riskCounts.UNASSESSED)],
      ['Overall CIS compliance', `${d.compliance.overallScorePct ?? '—'}%`],
      ...d.compliance.frameworks.map((f) => [f.label, `${f.scorePct ?? '—'}%`]),
      ['Devices on actively exploited firmware', String(d.exploitedDevices.length)],
      ['High-risk changes (7 days)', String(d.riskyChanges.length)],
      ['Changes awaiting approval', String(d.pendingApprovals)],
      ['Unreachable devices', String(d.unreachable)],
    ],
    headStyles: { fillColor: [15, 23, 42] },
  });

  const sections: Array<[string, string[], string[][]]> = [
    ['Most-failed rules', ['Rule', 'Title', 'Failing'], d.compliance.ruleFailures.filter((r) => r.failing).slice(0, 10).map((r) => [r.ruleId, r.title, `${r.failing}/${r.applicable}`])],
    ['Actively exploited firmware (CISA KEV)', ['Device', 'KEV CVEs'], d.exploitedDevices.map((x) => [x.hostname, String(x.kevCount)])],
    ['High-risk configuration changes', ['Device', 'Severity', 'Date', 'What changed'], d.riskyChanges.map((c) => [c.hostname, c.severity, c.when, c.summary])],
    ['Device inventory', ['Device', 'Risk', 'Status'], d.devices.map((x) => [x.hostname, x.risk, x.status])],
  ];
  for (const [title, head, body] of sections) {
    if (!body.length) continue;
    const y = ((doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY ?? 30) + 10;
    doc.setFontSize(11);
    doc.text(title, 14, y);
    autoTable(doc, { startY: y + 3, head: [head], body, headStyles: { fillColor: [15, 23, 42] }, styles: { fontSize: 8 } });
  }
  return Buffer.from(doc.output('arraybuffer')).toString('base64');
}

export async function sendDigests(admin: SupabaseClient, fetchImpl: typeof fetch = fetch): Promise<Array<{ orgId: string; delivered: string[]; errors: string[] }>> {
  const { data: orgs } = await admin.from('organizations').select('id');
  const { data: orgChannels } = await admin.from('alert_channels').select('*').eq('enabled', true);
  const results = [];

  for (const org of orgs || []) {
    const channels = [...envChannels(), ...((orgChannels || []) as AlertChannel[]).filter((c) => c.org_id === org.id)].filter((c) =>
      channelWants(c, { kind: 'weekly_digest', severity: 'LOW' })
    );
    if (!channels.length) continue;
    const data = await gatherDigest(admin, org.id);
    if (!data.devices.length) continue;

    const text = digestText(data);
    const pdf = digestPdf(data);
    const delivered: string[] = [];
    const errors: string[] = [];
    for (const channel of channels) {
      try {
        await sendToChannel(
          channel,
          { kind: 'weekly_digest', severity: 'LOW', title: `${data.orgName} weekly security digest`, body: text, device_id: null, created_at: data.generatedAt },
          fetchImpl,
          channel.kind === 'email' ? [{ filename: `aegisapex-digest-${data.generatedAt.slice(0, 10)}.pdf`, content: pdf }] : []
        );
        delivered.push(channel.name);
      } catch (err) {
        errors.push(`${channel.name}: ${err instanceof Error ? err.message : err}`);
      }
    }
    results.push({ orgId: org.id, delivered, errors });
  }
  return results;
}
