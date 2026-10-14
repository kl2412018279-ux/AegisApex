// dashboard/_components/AdminTab.tsx
import React, { useCallback, useEffect, useState } from 'react';
import { Users, Bell, ScrollText, Trash2, Send } from 'lucide-react';
import { toast } from 'sonner';
import type { Membership, Role } from '../_types/dashboard.types';
import { api, formatWhen } from '../_utils/api';
import { Card, CardTitle, Button, Empty, inputClass, muted } from './ui';

interface Member { user_id: string; role: Role; email: string; created_at: string }
interface Channel { id: string; name: string; kind: string; target: string; min_severity: string; events: string[]; enabled: boolean }
interface AlertRow { id: string; kind: string; severity: string; title: string; status: string; delivered: Record<string, string> | null; created_at: string }
interface AuditRow { id: number; actor_email: string | null; action: string; target_type: string | null; target_id: string | null; details: Record<string, unknown> | null; ip: string | null; created_at: string }

const EVENT_LABELS: Record<string, string> = {
  risk_increase: 'Risk increased',
  risky_change: 'Risky config change',
  kev_detected: 'Exploited CVE found',
  device_unreachable: 'Device unreachable',
  remediation_pending: 'Change awaiting approval',
  remediation_result: 'Change result',
  weekly_digest: 'Weekly digest',
};

export function AdminTab({ isDarkMode, memberships, currentUserId }: { isDarkMode: boolean; memberships: Membership[]; currentUserId: string | null }) {
  const adminOrgs = memberships.filter((m) => m.role === 'admin');
  const [orgId, setOrgId] = useState(adminOrgs[0]?.orgId || '');
  const [members, setMembers] = useState<Member[]>([]);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<AlertRow[]>([]);
  const [envChannels, setEnvChannels] = useState<string[]>([]);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [auditFilter, setAuditFilter] = useState('');
  const [memberForm, setMemberForm] = useState({ email: '', role: 'viewer' as Role });
  const [channelForm, setChannelForm] = useState({ name: '', kind: 'slack', target: '', minSeverity: 'HIGH', events: Object.keys(EVENT_LABELS) });

  const load = useCallback(async () => {
    if (!orgId) return;
    try {
      const [m, c, a] = await Promise.all([
        api<{ members: Member[] }>(`/api/admin/members?orgId=${orgId}`),
        api<{ channels: Channel[]; recentAlerts: AlertRow[]; envChannelsConfigured: string[] }>(`/api/admin/alert-channels?orgId=${orgId}`),
        api<{ entries: AuditRow[] }>(`/api/admin/audit?orgId=${orgId}&limit=200${auditFilter ? `&action=${encodeURIComponent(auditFilter)}` : ''}`),
      ]);
      setMembers(m.members);
      setChannels(c.channels);
      setRecentAlerts(c.recentAlerts);
      setEnvChannels(c.envChannelsConfigured);
      setAudit(a.entries);
    } catch (e: any) {
      toast.error('Could not load admin data', { description: e.message });
    }
  }, [orgId, auditFilter]);

  useEffect(() => {
    load();
  }, [load]);

  async function run(label: string, fn: () => Promise<unknown>) {
    try {
      await fn();
      toast.success(label);
      load();
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  if (!adminOrgs.length) return <Card isDarkMode={isDarkMode}><Empty>You are not an admin of any organization.</Empty></Card>;

  const th = `py-1.5 pr-3 font-semibold text-left ${muted(isDarkMode)}`;

  return (
    <div className="space-y-6">
      {adminOrgs.length > 1 && (
        <select className={`${inputClass(isDarkMode)} max-w-xs`} value={orgId} onChange={(e) => setOrgId(e.target.value)} aria-label="Organization">
          {adminOrgs.map((m) => <option key={m.orgId} value={m.orgId}>{m.orgName}</option>)}
        </select>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={Users}>Members</CardTitle>
          <table className="w-full text-xs mb-4">
            <thead><tr><th className={th}>User</th><th className={th}>Role</th><th className={th}><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.user_id} className="border-t border-slate-500/20">
                  <td className="py-1.5 pr-3">{m.email}{m.user_id === currentUserId ? ' (you)' : ''}</td>
                  <td className="py-1.5 pr-3">
                    <select
                      className={`rounded border px-1.5 py-0.5 text-xs ${isDarkMode ? 'bg-slate-950 border-slate-700' : 'bg-white border-slate-300'}`}
                      value={m.role}
                      onChange={(e) => run('Role updated', () => api('/api/admin/members', { method: 'POST', json: { orgId, email: m.email, role: e.target.value } }))}
                    >
                      <option value="viewer">viewer</option>
                      <option value="operator">operator</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td className="py-1.5 text-right">
                    <button
                      aria-label={`Remove ${m.email}`}
                      className="text-rose-500 hover:text-rose-400"
                      onClick={() => window.confirm(`Remove ${m.email} from this organization?`) && run('Member removed', () => api(`/api/admin/members?orgId=${orgId}&userId=${m.user_id}`, { method: 'DELETE' }))}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <form
            className="flex flex-wrap gap-2 items-end"
            onSubmit={(e) => {
              e.preventDefault();
              run('Member added (invited by email if new)', () => api('/api/admin/members', { method: 'POST', json: { orgId, ...memberForm } })).then(() => setMemberForm({ email: '', role: 'viewer' }));
            }}
          >
            <label className="text-[11px] font-semibold flex-1 min-w-[180px]">Email
              <input type="email" required className={`${inputClass(isDarkMode)} mt-1`} value={memberForm.email} onChange={(e) => setMemberForm({ ...memberForm, email: e.target.value })} />
            </label>
            <label className="text-[11px] font-semibold">Role
              <select className={`${inputClass(isDarkMode)} mt-1`} value={memberForm.role} onChange={(e) => setMemberForm({ ...memberForm, role: e.target.value as Role })}>
                <option value="viewer">viewer — read only</option>
                <option value="operator">operator — collect, scan, request changes</option>
                <option value="admin">admin — approve changes, manage org</option>
              </select>
            </label>
            <Button type="submit" tone="primary" isDarkMode={isDarkMode}>Add</Button>
          </form>
        </Card>

        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={Bell}>Alert channels</CardTitle>
          {envChannels.length > 0 && <p className={`text-[11px] mb-3 ${muted(isDarkMode)}`}>Also active for every org via env vars: {envChannels.join(', ')}</p>}
          {channels.length === 0 ? (
            <Empty>No channels yet.</Empty>
          ) : (
            <ul className="space-y-2 mb-4">
              {channels.map((c) => (
                <li key={c.id} className={`p-2.5 rounded-lg border text-xs flex justify-between gap-3 ${isDarkMode ? 'border-slate-800' : 'border-slate-200'}`}>
                  <div>
                    <div className="font-semibold">{c.name} <span className={muted(isDarkMode)}>· {c.kind} · ≥ {c.min_severity}</span></div>
                    <div className={`font-mono text-[10px] ${muted(isDarkMode)}`}>{c.target}</div>
                  </div>
                  <div className="flex gap-2 items-start">
                    <Button isDarkMode={isDarkMode} onClick={() => run('Test alert sent', () => api(`/api/admin/alert-channels?test=${c.id}`, { method: 'POST' }))}><Send className="w-3 h-3" />Test</Button>
                    <Button isDarkMode={isDarkMode} tone="danger" aria-label={`Delete ${c.name}`} onClick={() => window.confirm(`Delete channel ${c.name}?`) && run('Channel deleted', () => api(`/api/admin/alert-channels?id=${c.id}`, { method: 'DELETE' }))}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <form
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              run('Channel added', () => api('/api/admin/alert-channels', { method: 'POST', json: { orgId, ...channelForm } })).then(() => setChannelForm({ ...channelForm, name: '', target: '' }));
            }}
          >
            <div className="grid grid-cols-2 gap-2">
              <input required placeholder="Name" className={inputClass(isDarkMode)} value={channelForm.name} onChange={(e) => setChannelForm({ ...channelForm, name: e.target.value })} aria-label="Channel name" />
              <select className={inputClass(isDarkMode)} value={channelForm.kind} onChange={(e) => setChannelForm({ ...channelForm, kind: e.target.value })} aria-label="Channel type">
                <option value="slack">Slack webhook</option>
                <option value="teams">Teams webhook</option>
                <option value="webhook">Generic webhook (JSON)</option>
                <option value="email">Email (Resend)</option>
              </select>
            </div>
            <input required placeholder={channelForm.kind === 'email' ? 'ops@example.com, sec@example.com' : 'https://hooks…'} className={inputClass(isDarkMode)} value={channelForm.target} onChange={(e) => setChannelForm({ ...channelForm, target: e.target.value })} aria-label="Channel target" />
            <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px]">
              {Object.entries(EVENT_LABELS).map(([k, label]) => (
                <label key={k} className="flex items-center gap-1">
                  <input
                    type="checkbox"
                    checked={channelForm.events.includes(k)}
                    onChange={(e) => setChannelForm({ ...channelForm, events: e.target.checked ? [...channelForm.events, k] : channelForm.events.filter((x) => x !== k) })}
                  />
                  {label}
                </label>
              ))}
            </div>
            <div className="flex gap-2 items-center">
              <label className="text-[11px]">Minimum severity
                <select className={`ml-2 rounded border px-1.5 py-1 text-xs ${isDarkMode ? 'bg-slate-950 border-slate-700' : 'bg-white border-slate-300'}`} value={channelForm.minSeverity} onChange={(e) => setChannelForm({ ...channelForm, minSeverity: e.target.value })}>
                  {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <option key={s}>{s}</option>)}
                </select>
              </label>
              <Button type="submit" tone="primary" isDarkMode={isDarkMode} className="ml-auto">Add channel</Button>
            </div>
          </form>
          {recentAlerts.length > 0 && (
            <details className="mt-4">
              <summary className="text-xs font-semibold cursor-pointer">Recent alerts ({recentAlerts.length})</summary>
              <ul className="mt-2 space-y-1 text-[11px]">
                {recentAlerts.map((a) => (
                  <li key={a.id}>
                    <span className="font-mono">{formatWhen(a.created_at)}</span> · [{a.severity}] {a.title} · <strong>{a.status}</strong>
                    {a.delivered && Object.values(a.delivered).some((v) => v !== 'ok') && <span className="text-rose-500"> · {Object.entries(a.delivered).filter(([, v]) => v !== 'ok').map(([k, v]) => `${k}: ${v}`).join('; ')}</span>}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </Card>
      </div>

      <Card isDarkMode={isDarkMode}>
        <CardTitle
          icon={ScrollText}
          right={<input placeholder="Filter by action, e.g. remediation" className={`${inputClass(isDarkMode)} max-w-xs`} value={auditFilter} onChange={(e) => setAuditFilter(e.target.value)} aria-label="Filter audit log" />}
        >
          Audit log
        </CardTitle>
        {audit.length === 0 ? (
          <Empty>No audit entries.</Empty>
        ) : (
          <div className="overflow-auto max-h-[420px]">
            <table className="w-full text-[11px]">
              <thead><tr><th className={th}>When</th><th className={th}>Who</th><th className={th}>Action</th><th className={th}>Target</th><th className={th}>Details</th></tr></thead>
              <tbody>
                {audit.map((a) => (
                  <tr key={a.id} className="border-t border-slate-500/20 align-top">
                    <td className="py-1 pr-3 whitespace-nowrap font-mono">{formatWhen(a.created_at)}</td>
                    <td className="py-1 pr-3">{a.actor_email || '—'}{a.ip ? <div className={muted(isDarkMode)}>{a.ip}</div> : null}</td>
                    <td className="py-1 pr-3 font-mono font-semibold">{a.action}</td>
                    <td className="py-1 pr-3 font-mono">{a.target_type ? `${a.target_type}:${(a.target_id || '').slice(0, 8)}` : '—'}</td>
                    <td className={`py-1 font-mono break-all ${muted(isDarkMode)}`}>{a.details ? JSON.stringify(a.details) : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
