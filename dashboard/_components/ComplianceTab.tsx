// dashboard/_components/ComplianceTab.tsx
import React, { useEffect, useState } from 'react';
import { BarChart3, ShieldCheck, ListChecks } from 'lucide-react';
import { toast } from 'sonner';
import { api } from '../_utils/api';
import { Card, CardTitle, Empty, muted } from './ui';
import { RiskMixChart, ComplianceLine, TrendTable, type TrendPoint } from './charts';

interface ControlStatus {
  control: string;
  rules: string[];
  failingDevices: string[];
  assessedDevices: number;
}

interface TrendsResponse {
  trend: TrendPoint[];
  compliance: {
    assessedDevices: number;
    unassessedDevices: number;
    overallScorePct: number | null;
    frameworks: Array<{ framework: string; label: string; scorePct: number | null; controls: ControlStatus[] }>;
    ruleFailures: Array<{ ruleId: string; title: string; failing: number; applicable: number }>;
  };
}

function StatTile({ label, value, sub, isDarkMode }: { label: string; value: string; sub?: string; isDarkMode: boolean }) {
  return (
    <div className={`rounded-xl border p-4 ${isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'}`}>
      <div className={`text-[11px] font-semibold uppercase tracking-wide ${muted(isDarkMode)}`}>{label}</div>
      <div className="text-2xl font-bold mt-1 tabular-nums">{value}</div>
      {sub && <div className={`text-[11px] mt-0.5 ${muted(isDarkMode)}`}>{sub}</div>}
    </div>
  );
}

export function ComplianceTab({ isDarkMode }: { isDarkMode: boolean }) {
  const [days, setDays] = useState(30);
  const [data, setData] = useState<TrendsResponse | null>(null);
  const [framework, setFramework] = useState('pciDss4');
  const [showTable, setShowTable] = useState(false);

  useEffect(() => {
    setData(null);
    api<TrendsResponse>(`/api/trends?days=${days}`)
      .then(setData)
      .catch((e) => toast.error('Could not load trends', { description: e.message }));
  }, [days]);

  if (!data) return <Card isDarkMode={isDarkMode}><Empty>Loading fleet trends…</Empty></Card>;

  const today = data.trend[data.trend.length - 1];
  const fw = data.compliance.frameworks.find((f) => f.framework === framework) || data.compliance.frameworks[0];
  const hasHistory = data.trend.some((p) => p.devicesTracked > 0);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile isDarkMode={isDarkMode} label="CIS compliance" value={data.compliance.overallScorePct === null ? '—' : `${data.compliance.overallScorePct}%`} sub={`${data.compliance.assessedDevices} assessed · ${data.compliance.unassessedDevices} not yet scanned`} />
        <StatTile isDarkMode={isDarkMode} label="Critical devices" value={String(today?.CRITICAL ?? 0)} sub="latest combined rating" />
        <StatTile isDarkMode={isDarkMode} label="High-risk devices" value={String(today?.HIGH ?? 0)} />
        <StatTile isDarkMode={isDarkMode} label={fw?.label || 'Framework'} value={fw?.scorePct === null || !fw ? '—' : `${fw.scorePct}%`} sub="controls passing (device-weighted)" />
      </div>

      <Card isDarkMode={isDarkMode}>
        <CardTitle
          icon={BarChart3}
          right={
            <div className="flex items-center gap-2">
              <div role="group" aria-label="Time range" className="flex rounded-lg overflow-hidden border border-slate-500/30">
                {[7, 30, 90].map((d) => (
                  <button
                    key={d}
                    onClick={() => setDays(d)}
                    aria-pressed={days === d}
                    className={`px-2.5 py-1 text-[11px] font-semibold ${days === d ? (isDarkMode ? 'bg-slate-700 text-white' : 'bg-slate-800 text-white') : ''}`}
                  >
                    {d}d
                  </button>
                ))}
              </div>
              <button className="text-[11px] underline" onClick={() => setShowTable((v) => !v)}>{showTable ? 'Show charts' : 'Show table'}</button>
            </div>
          }
        >
          Devices by risk level
        </CardTitle>
        {!hasHistory ? (
          <Empty>No risk history yet. It builds up as devices are assessed.</Empty>
        ) : showTable ? (
          <div className="max-h-80 overflow-auto"><TrendTable points={data.trend} /></div>
        ) : (
          <RiskMixChart points={data.trend} isDarkMode={isDarkMode} />
        )}
      </Card>

      {hasHistory && !showTable && (
        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={ShieldCheck}>Average CIS compliance</CardTitle>
          <ComplianceLine points={data.trend} isDarkMode={isDarkMode} />
        </Card>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card isDarkMode={isDarkMode}>
          <CardTitle
            icon={ShieldCheck}
            right={
              <select className={`rounded border px-2 py-1 text-[11px] ${isDarkMode ? 'bg-slate-950 border-slate-700' : 'bg-white border-slate-300'}`} value={framework} onChange={(e) => setFramework(e.target.value)}>
                {data.compliance.frameworks.map((f) => <option key={f.framework} value={f.framework}>{f.label}</option>)}
              </select>
            }
          >
            Control posture
          </CardTitle>
          {!fw || data.compliance.assessedDevices === 0 ? (
            <Empty>Run an AI assessment on at least one device to see control posture.</Empty>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className={`text-left ${muted(isDarkMode)}`}>
                  <th className="py-1.5 pr-3 font-semibold">Control</th>
                  <th className="py-1.5 pr-3 font-semibold">Status</th>
                  <th className="py-1.5 font-semibold">Failing devices</th>
                </tr>
              </thead>
              <tbody>
                {fw.controls.map((c) => (
                  <tr key={c.control} className="border-t border-slate-500/20 align-top">
                    <td className="py-1.5 pr-3 font-mono">{c.control}<div className={`text-[10px] ${muted(isDarkMode)}`}>{c.rules.join(', ')}</div></td>
                    <td className="py-1.5 pr-3 whitespace-nowrap">
                      {c.assessedDevices === 0 ? <span className={muted(isDarkMode)}>n/a</span> : c.failingDevices.length ? <span>✖ {c.failingDevices.length}/{c.assessedDevices} failing</span> : <span>✔ passing</span>}
                    </td>
                    <td className="py-1.5 text-[11px]">{c.failingDevices.slice(0, 6).join(', ')}{c.failingDevices.length > 6 ? ` +${c.failingDevices.length - 6}` : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className={`text-[10px] mt-3 ${muted(isDarkMode)}`}>Mappings are indicative and cover only what device configuration can show. They are not a substitute for a formal assessment.</p>
        </Card>

        <Card isDarkMode={isDarkMode}>
          <CardTitle icon={ListChecks}>Most-failed rules</CardTitle>
          {data.compliance.ruleFailures.filter((r) => r.failing).length === 0 ? (
            <Empty>No failing rules across assessed devices.</Empty>
          ) : (
            <ul className="space-y-2.5">
              {data.compliance.ruleFailures.filter((r) => r.failing).slice(0, 12).map((r) => (
                <li key={r.ruleId} className="text-xs">
                  <div className="flex justify-between gap-3">
                    <span><span className="font-mono font-bold">{r.ruleId}</span> {r.title}</span>
                    <span className="font-mono shrink-0">{r.failing}/{r.applicable}</span>
                  </div>
                  <div className={`mt-1 h-1.5 rounded-full overflow-hidden ${isDarkMode ? 'bg-slate-800' : 'bg-slate-200'}`}>
                    <div className={`h-full rounded-full ${isDarkMode ? 'bg-indigo-400' : 'bg-indigo-600'}`} style={{ width: `${(r.failing / r.applicable) * 100}%` }} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
