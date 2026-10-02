// C:\Users\hp\aiops-securewatch\dashboard\_components\FleetPrintReport.tsx
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

      {/* Corporate Executive Header */}
      <div className="border-b-2 border-slate-900 pb-4 mb-5 flex justify-between items-end">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-slate-900" />
            <h1 className="text-sm font-black tracking-widest uppercase font-mono text-slate-900">
              AIOps SecureWatch
            </h1>
            <span className="text-xs font-mono font-bold text-slate-500">| ENTERPRISE FLEET AUDIT</span>
          </div>
          <p className="text-[9px] font-mono text-slate-500 uppercase tracking-widest mt-1">
            Infrastructure Threat Posture & Asset Compliance Matrix
          </p>
        </div>

        <div className="text-right font-mono text-[9px] space-y-0.5">
          <div className="inline-flex items-center gap-1 px-2 py-0.5 bg-slate-100 text-slate-900 border border-slate-400 font-bold text-[8px] uppercase tracking-wider mb-1">
            <Lock className="w-2.5 h-2.5 text-slate-700" /> CONFIDENTIAL // SOC RESTRICTED
          </div>
          <p className="text-slate-600">Generated: <span className="font-bold text-slate-900">{generatedDate}</span></p>
          <p className="text-slate-600">Total Scope: <span className="font-bold text-slate-900">{total} Assets</span></p>
        </div>
      </div>

      <div className="space-y-5">
        {/* Fleet KPI Summary Matrix */}
        <div className="avoid-break">
          <div className="text-[9px] font-mono uppercase font-bold text-slate-500 mb-1.5 flex justify-between border-b border-slate-300 pb-0.5">
            <span>Executive Fleet Summary</span>
            <span>Scope: All Registered Enterprise Managed Assets</span>
          </div>
          <table className="w-full text-center border-collapse border border-slate-300 text-[9.5px]">
            <thead>
              <tr className="bg-slate-50 text-slate-700 font-mono text-[8px] uppercase border-b border-slate-300">
                <th className="p-2 border-r border-slate-300 font-bold">Total Managed Assets</th>
                <th className="p-2 border-r border-slate-300 font-bold text-slate-900">Critical Threat Assets</th>
                <th className="p-2 border-r border-slate-300 font-bold text-slate-900">High / Medium Risks</th>
                <th className="p-2 font-bold text-slate-900">Fleet Posture Score</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="p-2.5 border-r border-slate-300 font-mono font-bold text-slate-900 text-sm">{total}</td>
                <td className="p-2.5 border-r border-slate-300 font-mono font-bold text-slate-900 text-sm">{criticals}</td>
                <td className="p-2.5 border-r border-slate-300 font-mono font-bold text-slate-900 text-sm">{highs + mediums}</td>
                <td className="p-2.5 font-mono font-bold text-slate-900 text-sm">
                  {compliant}%
                  {/* FIX: make the "of what" explicit on the printed report, since the
                      score now excludes never-scanned devices from the calculation */}
                  {unassessed > 0 && (
                    <div className="text-[7px] font-normal text-slate-500 normal-case">
                      of {assessed} assessed ({unassessed} unscanned excluded)
                    </div>
                  )}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Audit Inventory Table */}
        <div className="space-y-2 avoid-break">
          <div className="flex justify-between items-center border-b-2 border-slate-900 pb-1">
            <h2 className="text-[10.5px] font-black uppercase tracking-wider text-slate-900 flex items-center gap-1.5 font-mono">
              <Server className="w-3.5 h-3.5 text-slate-900" />
              Managed Asset Security Breakdown
            </h2>
            <span className="text-[9px] font-mono text-slate-600">
              Registered Nodes: <strong className="text-slate-900 font-bold">{total}</strong>
            </span>
          </div>

          <table className="w-full text-left border-collapse border border-slate-300 font-sans text-[9px]">
            <thead>
              <tr className="bg-slate-900 text-white font-mono text-[8px] uppercase tracking-wider">
                <th className="p-2 border border-slate-800">Hostname</th>
                <th className="p-2 border border-slate-800">Management IP</th>
                <th className="p-2 border border-slate-800">Vendor / Platform</th>
                <th className="p-2 border border-slate-800">Supplier Domain</th>
                <th className="p-2 border border-slate-800 text-center">Threat Level</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d, i) => {
                const r = d.risk_level || (d as any).riskLevel || 'LOW';
                const ip = d.ip_address || (d as any).management_ip || 'N/A';
                const platform = d.netmiko_type || (d as any).device_type || 'N/A';
                const supplier = d.suppliers?.name || (d as any).supplier?.name || 'Internal Ops';

                return (
                  <tr key={d.id || i} className="even:bg-slate-50 font-mono avoid-break">
                    <td className="p-2 font-bold text-slate-900 border border-slate-300">{d.hostname}</td>
                    <td className="p-2 text-slate-800 border border-slate-300">{ip}</td>
                    <td className="p-2 text-slate-700 border border-slate-300 uppercase">{`${d.vendor || 'Generic'} (${platform})`}</td>
                    <td className="p-2 text-slate-700 border border-slate-300">{supplier}</td>
                    <td className="p-2 text-center border border-slate-300">
                      <span className={`px-2 py-0.5 text-[7.5px] font-bold uppercase border inline-block ${getRiskColor(r, false).badge}`}>
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
        <div className="pt-3 border-t-2 border-slate-900 text-[8px] font-mono text-slate-500 flex justify-between items-end avoid-break">
          <div className="space-y-0.5">
            <p className="text-slate-900 font-bold flex items-center gap-1">
              <FileCheck className="w-3 h-3 text-slate-900" /> AIOps SecureWatch Platform Audit
            </p>
            <p className="text-slate-500">Enterprise Fleet Inventory and Operational Threat Matrix.</p>
          </div>
          <div className="text-right">
            <p className="text-slate-900 font-bold uppercase">Classification: Restricted</p>
            <p className="text-slate-500">Page 1 of 1</p>
          </div>
        </div>
      </div>
    </div>
  );
}
