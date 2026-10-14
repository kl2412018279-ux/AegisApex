// dashboard/_components/RemediationTab.tsx
import React, { useCallback, useEffect, useState } from 'react';
import { Wrench, Send, ShieldCheck, ChevronDown, ChevronRight } from 'lucide-react';
import { toast } from 'sonner';
import { supabase } from '@/lib/supabase';
import type { Device, ScanResult } from '../_types/dashboard.types';
import { api, formatWhen } from '../_utils/api';
import { Card, CardTitle, Button, Empty, RiskBadge, inputClass, muted } from './ui';

interface RemediationRequest {
  id: string;
  device_id: string;
  rule_id: string | null;
  title: string;
  commands: string;
  rollback_commands: string;
  status: string;
  requested_by: string;
  requested_by_email: string | null;
  approved_by_email: string | null;
  decision_note: string | null;
  output: string | null;
  created_at: string;
  updated_at: string;
  devices?: { hostname: string; org_id: string };
}

const STATUS_LABEL: Record<string, string> = {
  pending_approval: '⏳ Awaiting approval',
  approved: '✔ Approved — queued for agent',
  rejected: '✖ Rejected',
  executing: '⚙ Applying…',
  applied: '⚙ Applied — verifying',
  verified: '✅ Verified',
  verification_failed: '⚠ Verification failed',
  failed: '✖ Failed to apply',
  rolling_back: '↩ Rolling back…',
  rolled_back: '↩ Rolled back',
};

interface Props {
  isDarkMode: boolean;
  device: Device | null;
  latestScan: ScanResult | null;
  canOperate: boolean;
  isAdminFor: (orgId?: string | null) => boolean;
  userId: string | null;
  onPendingCount: (n: number) => void;
}

export function RemediationTab({ isDarkMode, device, latestScan, canOperate, isAdminFor, userId, onPendingCount }: Props) {
  const [requests, setRequests] = useState<RemediationRequest[]>([]);
  const [scope, setScope] = useState<'device' | 'all'>('all');
  const [form, setForm] = useState({ title: '', commands: '', rollbackCommands: '', ruleId: '' });
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const qs = scope === 'device' && device ? `?deviceId=${device.id}` : '';
      const data = await api<{ requests: RemediationRequest[] }>(`/api/remediation${qs}`);
      setRequests(data.requests);
      if (scope === 'all') onPendingCount(data.requests.filter((r) => r.status === 'pending_approval').length);
    } catch (e: any) {
      toast.error('Could not load change requests', { description: e.message });
    }
  }, [scope, device, onPendingCount]);

  useEffect(() => {
    load();
    const channel = supabase
      .channel('remediation-live')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'remediation_requests' }, () => load())
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [load]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!device) return;
    setBusy('create');
    try {
      await api('/api/remediation', {
        method: 'POST',
        json: { deviceId: device.id, title: form.title, commands: form.commands, rollbackCommands: form.rollbackCommands || undefined, ruleId: form.ruleId || undefined },
      });
      toast.success('Change request submitted', { description: 'An admin other than you must approve it.' });
      setForm({ title: '', commands: '', rollbackCommands: '', ruleId: '' });
      load();
    } catch (err: any) {
      toast.error('Could not submit', { description: err.message });
    } finally {
      setBusy(null);
    }
  }

  async function act(id: string, action: 'approve' | 'reject' | 'rollback' | 'cancel') {
    const prompts: Record<string, string> = {
      approve: 'Approve and push these commands to the device now?',
      rollback: 'Push the rollback commands to the device now?',
    };
    if (prompts[action] && !window.confirm(prompts[action])) return;
    const note = action === 'reject' ? window.prompt('Reason for rejecting (optional)') ?? undefined : undefined;
    setBusy(id);
    try {
      await api(`/api/remediation/${id}/${action}`, { method: 'POST', json: { note } });
      toast.success(`Request ${action === 'approve' ? 'approved' : action === 'rollback' ? 'rollback queued' : action + 'ed'}`);
      load();
    } catch (err: any) {
      toast.error(`Could not ${action}`, { description: err.message });
    } finally {
      setBusy(null);
    }
  }

  const findings = (latestScan?.vulnerabilities || []).filter((v) => v.remediation_cli);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
      <div className="xl:col-span-2 space-y-6">
        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={ShieldCheck}>Fix a finding</CardTitle>
          {!findings.length ? (
            <Empty>No open findings with a remediation for {device?.hostname || 'this device'}. Run an AI assessment first.</Empty>
          ) : (
            <ul className="space-y-2">
              {findings.map((f, i) => (
                <li key={f.id || i} className={`p-2.5 rounded-lg border text-xs flex items-start justify-between gap-3 ${isDarkMode ? 'border-slate-800' : 'border-slate-200'}`}>
                  <div>
                    <div className="flex items-center gap-2"><RiskBadge level={f.severity} isDarkMode={isDarkMode} /><span className="font-semibold">{f.title}</span></div>
                    {f.evidence && <code className={`block mt-1 text-[10px] break-all ${muted(isDarkMode)}`}>{f.evidence}</code>}
                  </div>
                  <Button
                    isDarkMode={isDarkMode}
                    className="whitespace-nowrap shrink-0"
                    disabled={!canOperate || device?.is_mock}
                    onClick={() => setForm({ title: f.title || 'Remediation', commands: f.remediation_cli || '', rollbackCommands: '', ruleId: f.rule_id || '' })}
                  >
                    Request fix
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={Send}>New change request · {device?.hostname || '—'}</CardTitle>
          {device?.is_mock ? (
            <Empty>Changes can&apos;t be pushed to mock devices.</Empty>
          ) : (
            <form onSubmit={submit} className="space-y-3">
              <label className="block text-[11px] font-semibold">Title
                <input className={`${inputClass(isDarkMode)} mt-1`} required maxLength={300} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
              </label>
              <label className="block text-[11px] font-semibold">Commands
                <textarea className={`${inputClass(isDarkMode)} mt-1 font-mono h-28`} required value={form.commands} onChange={(e) => setForm({ ...form, commands: e.target.value })} placeholder={'line vty 0 15\n transport input ssh'} />
              </label>
              <p className={`text-[10px] -mt-1 ${muted(isDarkMode)}`}>Replace any &lt;placeholders&gt; with real values before submitting.</p>
              <label className="block text-[11px] font-semibold">Rollback commands <span className={muted(isDarkMode)}>(optional — generated if empty)</span>
                <textarea className={`${inputClass(isDarkMode)} mt-1 font-mono h-20`} value={form.rollbackCommands} onChange={(e) => setForm({ ...form, rollbackCommands: e.target.value })} />
              </label>
              <Button type="submit" tone="primary" isDarkMode={isDarkMode} disabled={!canOperate || !device || busy === 'create' || /<[^>]+>/.test(form.commands)}>
                Submit for approval
              </Button>
              {!canOperate && <p className={`text-[11px] ${muted(isDarkMode)}`}>Requires the operator role.</p>}
            </form>
          )}
        </Card>
      </div>

      <Card isDarkMode={isDarkMode} className="xl:col-span-3">
        <CardTitle
          icon={Wrench}
          right={
            <div role="group" aria-label="Scope" className="flex rounded-lg overflow-hidden border border-slate-500/30 text-[11px] font-semibold">
              {(['all', 'device'] as const).map((s) => (
                <button key={s} onClick={() => setScope(s)} aria-pressed={scope === s} className={`px-2.5 py-1 ${scope === s ? (isDarkMode ? 'bg-slate-700 text-white' : 'bg-slate-800 text-white') : ''}`}>
                  {s === 'all' ? 'All devices' : 'This device'}
                </button>
              ))}
            </div>
          }
        >
          Change requests
        </CardTitle>
        {!requests.length ? (
          <Empty>No change requests yet.</Empty>
        ) : (
          <ul className="space-y-3">
            {requests.map((r) => {
              const admin = isAdminFor(r.devices?.org_id);
              const mine = r.requested_by === userId;
              const expanded = open === r.id;
              return (
                <li key={r.id} className={`rounded-lg border p-3 text-xs ${isDarkMode ? 'border-slate-800 bg-slate-950/50' : 'border-slate-200 bg-slate-50'}`}>
                  <div className="flex items-start justify-between gap-3">
                    <button className="text-left flex items-start gap-1.5" onClick={() => setOpen(expanded ? null : r.id)} aria-expanded={expanded}>
                      {expanded ? <ChevronDown className="w-3.5 h-3.5 mt-0.5" /> : <ChevronRight className="w-3.5 h-3.5 mt-0.5" />}
                      <span>
                        <span className="font-semibold">{r.title}</span>
                        <span className={`block text-[11px] ${muted(isDarkMode)}`}>
                          {r.devices?.hostname || r.device_id} · {r.rule_id ? `${r.rule_id} · ` : ''}by {r.requested_by_email || 'unknown'} · {formatWhen(r.created_at)}
                        </span>
                      </span>
                    </button>
                    <span className="whitespace-nowrap font-semibold">{STATUS_LABEL[r.status] || r.status}</span>
                  </div>

                  {expanded && (
                    <div className="mt-3 space-y-2">
                      <div>
                        <div className={`text-[10px] uppercase font-bold ${muted(isDarkMode)}`}>Commands</div>
                        <pre className={`mt-1 p-2 rounded font-mono text-[11px] whitespace-pre-wrap ${isDarkMode ? 'bg-slate-900' : 'bg-white border border-slate-200'}`}>{r.commands}</pre>
                      </div>
                      <div>
                        <div className={`text-[10px] uppercase font-bold ${muted(isDarkMode)}`}>Rollback</div>
                        <pre className={`mt-1 p-2 rounded font-mono text-[11px] whitespace-pre-wrap ${isDarkMode ? 'bg-slate-900' : 'bg-white border border-slate-200'}`}>{r.rollback_commands || '—'}</pre>
                      </div>
                      {r.approved_by_email && <p>Decided by {r.approved_by_email}</p>}
                      {r.decision_note && <p><strong>Note:</strong> {r.decision_note}</p>}
                      {r.output && (
                        <details>
                          <summary className="cursor-pointer font-semibold">Device output</summary>
                          <pre className={`mt-1 p-2 rounded font-mono text-[10px] whitespace-pre-wrap max-h-60 overflow-auto ${isDarkMode ? 'bg-slate-900' : 'bg-white border border-slate-200'}`}>{r.output}</pre>
                        </details>
                      )}
                    </div>
                  )}

                  <div className="flex flex-wrap gap-2 mt-3">
                    {r.status === 'pending_approval' && admin && !mine && (
                      <>
                        <Button tone="success" isDarkMode={isDarkMode} disabled={busy === r.id} onClick={() => act(r.id, 'approve')}>Approve & apply</Button>
                        <Button tone="danger" isDarkMode={isDarkMode} disabled={busy === r.id} onClick={() => act(r.id, 'reject')}>Reject</Button>
                      </>
                    )}
                    {r.status === 'pending_approval' && mine && (
                      <>
                        <span className={`text-[11px] self-center ${muted(isDarkMode)}`}>Waiting for another admin to approve.</span>
                        <Button isDarkMode={isDarkMode} disabled={busy === r.id} onClick={() => act(r.id, 'cancel')}>Cancel</Button>
                      </>
                    )}
                    {['applied', 'verified', 'verification_failed', 'failed'].includes(r.status) && admin && r.rollback_commands && (
                      <Button isDarkMode={isDarkMode} disabled={busy === r.id} onClick={() => act(r.id, 'rollback')}>Roll back</Button>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}
