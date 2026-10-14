// dashboard/lib/processing.ts
// Background work run by /api/cron/process: change tracking on new
// snapshots and verification of applied remediations.
import type { SupabaseClient } from '@supabase/supabase-js';
import { computeDrift } from './configDiff';
import { evaluateConfigDeterministically } from './cisBenchmarks';
import { queueAlert } from './alerts';

interface ConfigRow {
  id: string;
  device_id: string;
  raw_config: string | null;
  content: string | null;
  created_at: string;
  source?: string;
}

const text = (c: { raw_config?: string | null; content?: string | null } | null) => c?.raw_config || c?.content || '';

/** Diffs every snapshot not yet checked against the one before it. */
export async function processNewConfigurations(admin: SupabaseClient, limit = 50): Promise<number> {
  const { data: pending, error } = await admin
    .from('configurations')
    .select('id, device_id, raw_config, content, created_at, source')
    .is('drift_checked_at', null)
    .order('created_at', { ascending: true })
    .limit(limit);
  if (error) throw error;

  let processed = 0;
  for (const config of (pending || []) as ConfigRow[]) {
    const { data: previous } = await admin
      .from('configurations')
      .select('id, raw_config, content, source')
      .eq('device_id', config.device_id)
      .lt('created_at', config.created_at)
      .neq('source', 'synthetic')
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (previous && config.source !== 'synthetic') {
      const { data: device } = await admin.from('devices').select('hostname, vendor, netmiko_type, org_id').eq('id', config.device_id).maybeSingle();
      const report = computeDrift(text(previous), text(config), device?.netmiko_type || device?.vendor || 'generic');
      if (report.addedLines + report.removedLines > 0) {
        await admin.from('config_changes').upsert(
          {
            device_id: config.device_id,
            from_configuration_id: previous.id,
            to_configuration_id: config.id,
            added_lines: report.addedLines,
            removed_lines: report.removedLines,
            risky_changes: [...report.riskyChanges, ...report.newFindings.map((f) => ({ severity: 'MEDIUM', title: `New CIS failure: ${f}`, line: '', change: 'added' }))],
            severity: report.severity,
          },
          { onConflict: 'to_configuration_id' }
        );
        if (report.severity && (report.riskyChanges.length > 0 || report.newFindings.length > 0) && config.source !== 'post_remediation') {
          const lines = [
            ...report.riskyChanges.map((c) => `• [${c.severity}] ${c.title}${c.line ? ` — \`${c.line}\`` : ''}`),
            ...report.newFindings.map((f) => `• New CIS failure: ${f}`),
          ];
          await queueAlert(admin, {
            orgId: device?.org_id ?? null,
            deviceId: config.device_id,
            kind: 'risky_change',
            severity: report.severity,
            title: `Risky configuration change on ${device?.hostname || config.device_id}`,
            body: `+${report.addedLines} / -${report.removedLines} lines\n${lines.slice(0, 15).join('\n')}`,
          });
        }
      }
    }
    await admin.from('configurations').update({ drift_checked_at: new Date().toISOString() }).eq('id', config.id);
    processed++;
  }
  return processed;
}

/** Re-runs the CIS rules on the post-change snapshot of applied remediations. */
export async function verifyAppliedRemediations(admin: SupabaseClient, limit = 20): Promise<number> {
  const { data: applied, error } = await admin
    .from('remediation_requests')
    .select('*')
    .eq('status', 'applied')
    .not('post_configuration_id', 'is', null)
    .limit(limit);
  if (error) throw error;

  for (const req of applied || []) {
    const [{ data: post }, { data: pre }, { data: device }] = await Promise.all([
      admin.from('configurations').select('raw_config, content').eq('id', req.post_configuration_id).maybeSingle(),
      admin.from('configurations').select('raw_config, content').eq('id', req.pre_configuration_id).maybeSingle(),
      admin.from('devices').select('hostname, vendor, netmiko_type, org_id').eq('id', req.device_id).maybeSingle(),
    ]);
    const vendor = device?.netmiko_type || device?.vendor || 'generic';
    const after = evaluateConfigDeterministically(text(post), vendor).findings.map((f) => f.ruleId);
    const before = new Set(evaluateConfigDeterministically(text(pre), vendor).findings.map((f) => f.ruleId));
    const regressions = after.filter((id) => !before.has(id));
    const targetFixed = req.rule_id ? !after.includes(req.rule_id) : true;
    const ok = targetFixed && regressions.length === 0;

    const note = [
      req.rule_id ? (targetFixed ? `${req.rule_id} now passes.` : `${req.rule_id} is STILL failing after the change.`) : 'No target rule; checked for regressions only.',
      regressions.length ? `New failures introduced: ${regressions.join(', ')}.` : 'No new CIS failures introduced.',
    ].join(' ');

    await admin
      .from('remediation_requests')
      .update({ status: ok ? 'verified' : 'verification_failed', decision_note: note, updated_at: new Date().toISOString() })
      .eq('id', req.id);
    await queueAlert(admin, {
      orgId: device?.org_id ?? null,
      deviceId: req.device_id,
      kind: 'remediation_result',
      severity: ok ? 'LOW' : 'HIGH',
      title: `${ok ? 'Verified' : 'Verification failed'}: ${req.title} on ${device?.hostname || req.device_id}`,
      body: note,
    });
  }
  return (applied || []).length;
}
