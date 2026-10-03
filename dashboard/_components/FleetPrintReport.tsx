//dashboard\_components\FleetPrintReport.tsx
import React from 'react';
import { Shield, Server, Lock, FileCheck } from 'lucide-react';
import { Device } from '../_types/dashboard.types';
import { getRiskColor } from '../_utils/riskHelpers';

interface FleetPrintReportProps {
  devices: Device[];
  generatedDate: string;
}

export function FleetPrintReport({ devices, generatedDate }: FleetPrintReportProps) {
  const total = devices.length;
  const criticals = devices.filter((d) => (d.risk_level || (d as any).riskLevel) === 'CRITICAL').length;
  const highs = devices.filter((d) => (d.risk_level || (d as any).riskLevel) === 'HIGH').length;
  const mediums = devices.filter((d) => (d.risk_level || (d as any).riskLevel) === 'MEDIUM').length;
  // FIX: the original formula was (total - criticals - highs) / total, which
  // silently counts every never-scanned device (UNASSESSED / undefined
  // risk_level) as "compliant". A fresh fleet of 100 devices that has never
  // been audited reported a 100% posture score. Compliance can only be
  // claimed for devices that have actually been assessed; unscanned devices
  // are neither compliant nor non-compliant, they're unknown, and are now
  // excluded from both sides of the ratio.
  const unassessed = devices.filter((d) => {
    const r = (d.risk_level || (d as any).riskLevel || '').toUpperCase();
    return !r || r === 'UNASSESSED';
  }).length;
  const assessed = total - unassessed;
  const compliant = assessed > 0 ? Math.round(((assessed - (criticals + highs)) / assessed) * 100) : 0;

  const kpis: { label: string; value: string | number; sub?: string }[] = [
    { label: 'Total Managed Assets', value: total },
    { label: 'Critical Threat Assets', value: criticals },
    { label: 'High / Medium Risk', value: highs + mediums },
    {
      label: 'Fleet Posture Score',
      value: `${compliant}%`,
      // FIX: make the "of what" explicit on the printed report, since the
      // score now excludes never-scanned devices from the calculation
      sub: unassessed > 0 ? `of ${assessed} assessed · ${unassessed} unscanned excluded` : undefined,
    },
  ];

  return (
    <div
      className="printable-active-target font-sans text-slate-900 bg-white mx-auto text-xs leading-normal p-6"
      style={{
        width: '210mm',
        minHeight: '297mm',
        boxSizing: 'border-box',
        WebkitPrintColorAdjust: 'exact',
        printColorAdjust: 'exact',
      }}
    >
      <style>{`
        @media print {
          @page {
            size: A4 portrait;
            margin: 8mm;
          }
          body {
            background: #ffffff !important;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }
          .printable-active-target {
            width: 100% !important;
            margin: 0 !important;
            padding: 0 !important;
            box-shadow: none !important;
            border: none !important;
          }
          .avoid-break {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
          }
        }
      `}</style>

      {/* Header */}
      <div className="flex items-start justify-between pb-5 mb-6 border-b border-slate-200">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-md bg-slate-900 flex items-center justify-center shrink-0">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-[15px] font-semibold text-slate-900 tracking-tight leading-none">
              AegisApex
            </h1>
            <p className="text-[11px] text-slate-500 mt-1">Enterprise Fleet Security Audit Report</p>
          </div>
        </div>

        <div className="text-right text-[10.5px] text-slate-500 space-y-1.5">
          <span className="inline-flex items-center gap-1 text-[9.5px] font-medium text-slate-600 bg-slate-100 rounded px-2 py-0.5">
            <Lock className="w-2.5 h-2.5" /> Confidential
          </span>
          <p>Generated <span className="font-medium text-slate-900">{generatedDate}</span></p>
          <p>Scope <span className="font-medium text-slate-900">{total} assets</span></p>
        </div>
      </div>

      <div className="space-y-6">
        {/* Fleet KPI Summary */}
        <div className="grid grid-cols-4 gap-3 avoid-break">
          {kpis.map((kpi) => (
            <div key={kpi.label} className="border border-slate-200 rounded-lg p-3.5">
              <p className="text-[9.5px] uppercase tracking-wide text-slate-400 font-medium mb-1.5 leading-tight">
                {kpi.label}
              </p>
              <p className="text-2xl font-semibold text-slate-900 leading-none">{kpi.value}</p>
              {kpi.sub && <p className="text-[9px] text-slate-400 mt-1.5 leading-snug">{kpi.sub}</p>}
            </div>
          ))}
        </div>

        {/* Audit Inventory Table */}
        <div className="avoid-break">
          <div className="flex justify-between items-center mb-2.5">
            <h2 className="text-[13px] font-semibold text-slate-900 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-slate-400" />
              Managed Asset Security Breakdown
            </h2>
            <span className="text-[10px] text-slate-500">
              {total} node{total === 1 ? '' : 's'}
            </span>
          </div>

          <table className="w-full text-left border border-slate-200 rounded-md text-[10px]" style={{ borderCollapse: 'separate', borderSpacing: 0 }}>
            <thead>
              <tr className="bg-slate-50 text-slate-500 text-[9px] font-medium uppercase tracking-wide">
                <th className="p-2.5 border-b border-slate-200">Hostname</th>
                <th className="p-2.5 border-b border-slate-200">Management IP</th>
                <th className="p-2.5 border-b border-slate-200">Vendor / Platform</th>
                <th className="p-2.5 border-b border-slate-200">Supplier</th>
                <th className="p-2.5 border-b border-slate-200 text-center">Threat Level</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d, i) => {
                const r = d.risk_level || (d as any).riskLevel || 'LOW';
                const ip = d.ip_address || (d as any).management_ip || 'N/A';
                const platform = d.netmiko_type || (d as any).device_type || 'N/A';
                const supplier = d.suppliers?.name || (d as any).supplier?.name || 'Internal Ops';

                return (
                  <tr key={d.id || i} className="avoid-break border-b border-slate-100 last:border-0 even:bg-slate-50/60">
                    <td className="p-2.5 font-medium text-slate-900">{d.hostname}</td>
                    <td className="p-2.5 text-slate-600">{ip}</td>
                    <td className="p-2.5 text-slate-600">{`${d.vendor || 'Generic'} (${platform})`}</td>
                    <td className="p-2.5 text-slate-600">{supplier}</td>
                    <td className="p-2.5 text-center">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wide inline-block ${getRiskColor(r, false).badge}`}>
                        {r}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-slate-200 text-[9px] text-slate-400 flex justify-between items-center avoid-break">
          <div className="flex items-center gap-1.5">
            <FileCheck className="w-3 h-3 text-slate-400" />
            <span>AegisApex &middot; Enterprise Fleet Inventory and Operational Threat Matrix</span>
          </div>
          <span>Page 1 of 1</span>
        </div>
      </div>
    </div>
  );
}