// dashboard/_components/ChangesTab.tsx
import React, { useCallback, useEffect, useState } from 'react';
import { GitCompare, KeyRound, Clock, AlertTriangle, History, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import type { Device } from '../_types/dashboard.types';
import { api, formatWhen } from '../_utils/api';
import { Card, CardTitle, Button, RiskBadge, Empty, inputClass, muted } from './ui';

interface Snapshot {
  id: string;
  created_at: string;
  source: string;
}

interface RiskyChange {
  severity: string;
  title: string;
  line: string;
  change: 'added' | 'removed';
}

type DiffRow = { type: 'add' | 'del' | 'same'; text: string } | { type: 'gap'; count: number };

interface DriftResponse {
  snapshots: Snapshot[];
  history: Array<{ id: string; added_lines: number; removed_lines: number; severity: string | null; risky_changes: RiskyChange[]; created_at: string; to_configuration_id: string; from_configuration_id: string }>;
  report: null | {
    addedLines: number;
    removedLines: number;
    lines: DiffRow[];
    riskyChanges: RiskyChange[];
    newFindings: string[];
    resolvedFindings: string[];
    severity: string | null;
  };
  from?: { id: string; created_at: string };
  to?: { id: string; created_at: string };
  message?: string;
}

const INTERVALS: Array<[number, string]> = [
  [15, 'Every 15 minutes'],
  [60, 'Hourly'],
  [240, 'Every 4 hours'],
  [1440, 'Daily'],
  [10080, 'Weekly'],
];

const SOURCE_LABEL: Record<string, string> = { ssh: 'SSH', synthetic: 'SYNTHETIC demo', manual: 'manual', post_remediation: 'after approved change' };

interface Props {
  isDarkMode: boolean;
  device: Device | null;
  canOperate: boolean;
  isAdmin: boolean;
  onDeviceUpdated: () => void;
}

export function ChangesTab({ isDarkMode, device, canOperate, isAdmin, onDeviceUpdated }: Props) {
  const [drift, setDrift] = useState<DriftResponse | null>(null);
  const [from, setFrom] = useState<string>('');
  const [to, setTo] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  const load = useCallback(
    async (fromId?: string, toId?: string) => {
      if (!device) return;
      setLoading(true);
      try {
        const qs = new URLSearchParams({ deviceId: device.id, ...(fromId ? { from: fromId } : {}), ...(toId ? { to: toId } : {}) });
        const data = await api<DriftResponse>(`/api/drift?${qs}`);
        setDrift(data);
        setFrom(data.from?.id || '');
        setTo(data.to?.id || '');
      } catch (e: any) {
        toast.error('Could not load configuration history', { description: e.message });
      } finally {
        setLoading(false);
      }
    },
    [device]
  );

  useEffect(() => {
    setDrift(null);
    load();
  }, [load]);

  async function saveSettings(body: Record<string, unknown>, success: string) {
    if (!device) return;
    setSaving(true);
    try {
      await api('/api/devices/settings', { method: 'POST', json: { deviceId: device.id, ...body } });
      toast.success(success);
      onDeviceUpdated();
    } catch (e: any) {
      toast.error('Update failed', { description: e.message });
    } finally {
      setSaving(false);
    }
  }

  if (!device) return <Card isDarkMode={isDarkMode}><Empty>Select a device.</Empty></Card>;

  const report = drift?.report;
  const lineClass = (t: string) =>
    t === 'add'
      ? isDarkMode ? 'bg-emerald-500/10 text-emerald-300' : 'bg-emerald-50 text-emerald-800'
      : t === 'del'
      ? isDarkMode ? 'bg-rose-500/10 text-rose-300 line-through decoration-rose-500/40' : 'bg-rose-50 text-rose-800 line-through decoration-rose-300'
      : muted(isDarkMode);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
      <div className="space-y-6 xl:col-span-1">
        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={Clock}>Collection</CardTitle>
          <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-2 text-xs">
            <dt className={muted(isDarkMode)}>Status</dt>
            <dd className="font-mono font-bold">{device.connection_status}{device.is_mock ? ' · MOCK' : ''}</dd>
            <dt className={muted(isDarkMode)}>Last collected</dt>
            <dd>{formatWhen(device.last_seen_at)}</dd>
            <dt className={muted(isDarkMode)}>Next scheduled</dt>
            <dd>{device.is_mock ? 'Not scheduled (mock)' : formatWhen(device.next_collection_at)}</dd>
          </dl>
          {device.last_collection_error && (
            <p className={`mt-3 p-2 rounded border text-[11px] flex gap-2 ${isDarkMode ? 'border-rose-800 bg-rose-950/40 text-rose-200' : 'border-rose-200 bg-rose-50 text-rose-800'}`}>
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden />
              <span><strong>Last error:</strong> {device.last_collection_error}</span>
            </p>
          )}
          <label className="block mt-4 text-[11px] font-semibold mb-1" htmlFor="interval">Collection schedule</label>
          <select
            id="interval"
            className={inputClass(isDarkMode)}
            disabled={!canOperate || saving || device.is_mock}
            value={device.collection_interval_minutes ?? 60}
            onChange={(e) => saveSettings({ collectionIntervalMinutes: Number(e.target.value) }, 'Schedule updated')}
          >
            {INTERVALS.map(([m, label]) => <option key={m} value={m}>{label}</option>)}
          </select>
          <label className="flex items-center gap-2 mt-3 text-xs">
            <input
              type="checkbox"
              checked={!!device.is_mock}
              disabled={!canOperate || saving}
              onChange={(e) => saveSettings({ isMock: e.target.checked }, e.target.checked ? 'Device marked as mock (demo data only)' : 'Device marked as real')}
            />
            Demo / mock device (never contacted over SSH)
          </label>
        </Card>

        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={KeyRound}>SSH host key</CardTitle>
          {device.ssh_host_key_fingerprint ? (
            <>
              <p className="font-mono text-[11px] break-all">{device.ssh_host_key_fingerprint}</p>
              <p className={`text-[11px] mt-1 ${muted(isDarkMode)}`}>Pinned {formatWhen(device.ssh_host_key_pinned_at)}. Connections presenting any other key are refused.</p>
              {isAdmin && (
                <Button
                  isDarkMode={isDarkMode}
                  tone="danger"
                  className="mt-3"
                  disabled={saving}
                  onClick={() => {
                    if (window.confirm('Only reset the pinned key after verifying the device was replaced or re-keyed. The next connection will trust whatever key it sees. Continue?')) {
                      saveSettings({ resetHostKey: true }, 'Pinned host key cleared; the next collection pins the new key');
                    }
                  }}
                >
                  Reset pinned key
                </Button>
              )}
            </>
          ) : (
            <p className={`text-xs ${muted(isDarkMode)}`}>Not pinned yet. The agent pins the key on the first successful connection.</p>
          )}
        </Card>

        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={History}>Change history</CardTitle>
          {drift?.history?.length ? (
            <ul className="space-y-2">
              {drift.history.map((h) => (
                <li key={h.id}>
                  <button
                    className={`w-full text-left p-2 rounded border text-[11px] ${isDarkMode ? 'border-slate-800 hover:bg-slate-800/60' : 'border-slate-200 hover:bg-slate-50'}`}
                    onClick={() => load(h.from_configuration_id, h.to_configuration_id)}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span>{formatWhen(h.created_at)}</span>
                      {h.severity ? <RiskBadge level={h.severity} isDarkMode={isDarkMode} /> : <span className={muted(isDarkMode)}>no risky changes</span>}
                    </div>
                    <div className={`mt-1 font-mono ${muted(isDarkMode)}`}>
                      +{h.added_lines} / −{h.removed_lines}
                      {h.risky_changes?.length ? ` · ${h.risky_changes.slice(0, 2).map((r) => r.title).join('; ')}` : ''}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No changes recorded yet. Changes are tracked as new snapshots are collected.</Empty>
          )}
        </Card>
      </div>

      <Card isDarkMode={isDarkMode} className="xl:col-span-2">
        <CardTitle
          icon={GitCompare}
          right={
            <Button isDarkMode={isDarkMode} onClick={() => load(from, to)} disabled={loading}>
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden /> Refresh
            </Button>
          }
        >
          Compare snapshots
        </CardTitle>

        {drift?.snapshots && drift.snapshots.length >= 2 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
            {([['From', from, setFrom], ['To', to, setTo]] as const).map(([label, value, set]) => (
              <label key={label} className="text-[11px] font-semibold">
                {label}
                <select
                  className={`${inputClass(isDarkMode)} mt-1`}
                  value={value}
                  onChange={(e) => {
                    set(e.target.value);
                    label === 'From' ? load(e.target.value, to) : load(from, e.target.value);
                  }}
                >
                  {drift.snapshots.map((s) => (
                    <option key={s.id} value={s.id}>{formatWhen(s.created_at)} · {SOURCE_LABEL[s.source] || s.source}</option>
                  ))}
                </select>
              </label>
            ))}
          </div>
        )}

        {!report ? (
          <Empty>{loading ? 'Loading…' : drift?.message || 'No comparison available.'}</Empty>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-3 mb-4 text-xs">
              <span className="font-mono"><span className="text-emerald-500 font-bold">+{report.addedLines}</span> / <span className="text-rose-500 font-bold">−{report.removedLines}</span> lines</span>
              {report.severity ? <span className="flex items-center gap-1.5">Change risk <RiskBadge level={report.severity} isDarkMode={isDarkMode} /></span> : <span className={muted(isDarkMode)}>No risky changes detected</span>}
            </div>

            {(report.riskyChanges.length > 0 || report.newFindings.length > 0 || report.resolvedFindings.length > 0) && (
              <ul className="space-y-1.5 mb-4">
                {report.riskyChanges.map((c, i) => (
                  <li key={`r${i}`} className="flex items-start gap-2 text-xs">
                    <RiskBadge level={c.severity} isDarkMode={isDarkMode} />
                    <span>
                      <strong>{c.title}</strong> <span className={muted(isDarkMode)}>({c.change})</span>
                      {c.line && <code className="block font-mono text-[11px] mt-0.5 break-all">{c.line}</code>}
                    </span>
                  </li>
                ))}
                {report.newFindings.map((f) => (
                  <li key={f} className="text-xs">⚠️ <strong>Now failing:</strong> {f}</li>
                ))}
                {report.resolvedFindings.map((f) => (
                  <li key={f} className="text-xs">✅ <strong>Now passing:</strong> {f}</li>
                ))}
              </ul>
            )}

            <div className={`rounded-lg border overflow-auto max-h-[560px] font-mono text-[11px] leading-5 ${isDarkMode ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              {report.addedLines + report.removedLines === 0 ? (
                <Empty>The two snapshots are identical (ignoring timestamps and other noise).</Empty>
              ) : (
                report.lines.map((l, i) =>
                  l.type === 'gap' ? (
                    <div key={i} className={`px-3 py-0.5 text-center text-[10px] ${muted(isDarkMode)} ${isDarkMode ? 'bg-slate-900' : 'bg-slate-100'}`}>
                      ⋯ {l.count} unchanged line{l.count === 1 ? '' : 's'} ⋯
                    </div>
                  ) : (
                    <div key={i} className={`px-3 whitespace-pre-wrap break-all ${lineClass(l.type)}`}>
                      <span aria-hidden className="select-none inline-block w-4">{l.type === 'add' ? '+' : l.type === 'del' ? '−' : ' '}</span>
                      <span className="sr-only">{l.type === 'add' ? 'added: ' : l.type === 'del' ? 'removed: ' : ''}</span>
                      {l.text || ' '}
                    </div>
                  )
                )
              )}
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
