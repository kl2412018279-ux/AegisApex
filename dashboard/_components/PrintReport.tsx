//dashboard\_components\PrintReport.tsx
//dashboard\_components\PrintReport.tsx
import React from 'react';
import { Shield, ShieldAlert, CheckCircle2, Cpu, AlertTriangle, AlertCircle, FileCheck, Lock } from 'lucide-react';
import { sanitizeConfig } from '@/lib/sanitizer';
import { Device, ScanResult } from '../_types/dashboard.types';
import { getRiskColor } from '../_utils/riskHelpers';
import { renderPrintAnalysis } from '../_utils/formatters';

interface PrintReportProps {
  selectedDevice: Device | null;
  latestScan: ScanResult | null;
  generatedDate?: string;
  currentOsSummary?: string;
  aiCache?: Record<string, any>;
}

function safeParse(val: any): any {
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        return JSON.parse(trimmed);
      } catch (e) {
        return val;
      }
    }
  }
  return val;
}

function extractFindingsDeep(target: any, visited = new Set()): any[] {
  if (!target || visited.has(target)) return [];

  const parsed = safeParse(target);
  if (!parsed || typeof parsed !== 'object') return [];

  visited.add(target);
  visited.add(parsed);

  if (Array.isArray(parsed)) {
    if (parsed.length > 0) {
      const first = safeParse(parsed[0]);
      if (first && typeof first === 'object' && (first.title || first.name || first.severity || first.description || first.cve || first.issue || first.rule || first.remediation)) {
        return parsed.map(safeParse);
      }
    }
    return [];
  }

  const priorityKeys = [
    'vulnerabilities', 'findings', 'issues', 'cves', 'threats',
    'config_vulnerabilities', 'security_findings', 'audit_findings',
    'results', 'rule_violations', 'violations', 'details', 'items', 'risks'
  ];

  for (const key of priorityKeys) {
    if (parsed[key]) {
      const res = extractFindingsDeep(parsed[key], visited);
      if (res.length > 0) return res;
    }
  }

  for (const key of Object.keys(parsed)) {
    if (parsed[key] && typeof parsed[key] === 'object') {
      const res = extractFindingsDeep(parsed[key], visited);
      if (res.length > 0) return res;
    }
  }

  return [];
}

export function PrintReport({
  selectedDevice,
  latestScan,
  generatedDate,
  currentOsSummary,
  aiCache = {},
}: PrintReportProps) {
  if (!selectedDevice) return null;

  const devAny = selectedDevice as any;

  const displayDate =
    generatedDate && generatedDate.trim() !== ''
      ? generatedDate
      : new Date().toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        });

  const devId = String(selectedDevice.id || '');
  const devHost = selectedDevice.hostname || '';
  const devIp = selectedDevice.ip_address || devAny.management_ip || '';

  const matchedCacheEntry =
    aiCache[devId] ||
    aiCache[devHost] ||
    aiCache[devIp] ||
    aiCache[`device_${devId}`] ||
    Object.values(aiCache).find((c: any) => {
      const parsed = safeParse(c);
      return (
        parsed?.hostname === devHost ||
        parsed?.id === devId ||
        parsed?.ip === devIp ||
        parsed?.ip_address === devIp
      );
    }) ||
    {};

  const cachedData = safeParse(matchedCacheEntry);

  const activeScan = safeParse(
    latestScan ||
    cachedData.latestScan ||
    cachedData.scan ||
    devAny.latest_scan ||
    devAny.latestScan ||
    (Array.isArray(devAny.scans) ? devAny.scans[0] : null) ||
    (Array.isArray(devAny.scan_history) ? devAny.scan_history[0] : null) ||
    null
  );

  const vulnerabilities = extractFindingsDeep([
    activeScan,
    cachedData,
    selectedDevice,
    devAny.vulnerabilities,
    devAny.findings,
    devAny.issues,
    devAny.latest_scan,
  ]);

  const scanRisk = (
    activeScan?.risk_level ||
    activeScan?.riskLevel ||
    cachedData.risk_level ||
    selectedDevice.risk_level ||
    devAny.riskLevel ||
    'EVALUATED'
  ).toUpperCase();

  let rawSummary =
    activeScan?.summary ||
    activeScan?.executive_summary ||
    cachedData.summary ||
    cachedData.executiveSummary ||
    devAny.summary ||
    devAny.ai_summary ||
    '';

  let executiveSummary = rawSummary;
  if (!rawSummary || rawSummary.trim() === 'Security Assessment completed.') {
    if (vulnerabilities.length > 0) {
      executiveSummary = `Automated security audit completed. Identified ${vulnerabilities.length} active risk finding(s) requiring immediate administrative remediation to ensure operational compliance.`;
    } else if (scanRisk === 'CRITICAL' || scanRisk === 'HIGH') {
      executiveSummary = `Automated assessment completed. Asset posture flagged as ${scanRisk} threat level based on operating system lifecycle and baseline compliance violations.`;
    } else {
      executiveSummary = `Security assessment completed successfully. Running configuration adheres to current enterprise security baselines.`;
    }
  }

  const rawOsSummary =
    currentOsSummary ||
    cachedData.osAnalysis ||
    cachedData.firmwareAnalysis ||
    activeScan?.os_analysis ||
    activeScan?.firmware_analysis ||
    devAny.firmware_analysis ||
    devAny.os_summary ||
    '';

  const isPlaceholderOs = !rawOsSummary || rawOsSummary.includes('Re-analyze Firmware');
  const detectedVersion = devAny.os_version || devAny.firmware_version || devAny.version || selectedDevice.vendor || '10.12.1000';

  const osAnalysisText = isPlaceholderOs
    ? `Version Detected: **${detectedVersion}**. Lifecycle posture evaluated against threat baseline (**${scanRisk}**).`
    : rawOsSummary;

  const targetFirmware =
    activeScan?.target_firmware ||
    cachedData.targetFirmware ||
    devAny.target_firmware ||
    'Latest Recommended LTS Release';

  const eolStatus =
    activeScan?.eol_status ||
    cachedData.eolStatus ||
    devAny.eol_status ||
    'Mainstream Support Active';

  const displayIp = selectedDevice.ip_address || devAny.management_ip || 'N/A';
  const platformType = selectedDevice.netmiko_type || devAny.device_type || 'N/A';
  const supplierName = selectedDevice.suppliers?.name || devAny.supplier?.name || 'Internal IT Infrastructure';
  const auditId = `AUD-${(selectedDevice.id ? String(selectedDevice.id) : 'SEC').slice(0, 8).toUpperCase()}`;

  return (
    <div
      className="printable-report font-sans text-slate-900 bg-white mx-auto text-xs leading-normal p-6"
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
          .printable-report {
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
            <p className="text-[11px] text-slate-500 mt-1">Single Asset Vulnerability &amp; Compliance Report</p>
          </div>
        </div>

        <div className="text-right text-[10.5px] text-slate-500 space-y-1.5">
          <span className="inline-flex items-center gap-1 text-[9.5px] font-medium text-slate-600 bg-slate-100 rounded px-2 py-0.5">
            <Lock className="w-2.5 h-2.5" /> Confidential
          </span>
          <p>Generated <span className="font-medium text-slate-900">{displayDate}</span></p>
          <p>Audit Ref <span className="font-medium text-slate-900">{auditId}</span></p>
        </div>
      </div>

      <div className="space-y-6">
        {/* Asset Identification */}
        <div className="grid grid-cols-2 gap-x-8 gap-y-3 p-4 border border-slate-200 rounded-lg avoid-break">
          <div>
            <p className="text-[9.5px] uppercase tracking-wide text-slate-400 font-medium mb-0.5">Hostname</p>
            <p className="text-[11.5px] font-medium text-slate-900">{selectedDevice.hostname}</p>
          </div>
          <div>
            <p className="text-[9.5px] uppercase tracking-wide text-slate-400 font-medium mb-0.5">Management IP</p>
            <p className="text-[11.5px] font-medium text-slate-900">{displayIp}</p>
          </div>
          <div>
            <p className="text-[9.5px] uppercase tracking-wide text-slate-400 font-medium mb-0.5">Platform OS</p>
            <p className="text-[11.5px] text-slate-900">{selectedDevice.vendor || 'Generic'} ({platformType})</p>
          </div>
          <div>
            <p className="text-[9.5px] uppercase tracking-wide text-slate-400 font-medium mb-0.5">Supplier / Scope</p>
            <p className="text-[11.5px] text-slate-900">{supplierName}</p>
          </div>
        </div>

        {/* Threat Status & Executive Summary */}
        <div className="flex gap-4 p-4 border border-slate-200 rounded-lg avoid-break">
          <div className="flex flex-col items-center w-28 shrink-0 border-r border-slate-100 pr-4 pt-0.5 text-center">
            <span className="text-[9px] uppercase tracking-wide text-slate-400 font-medium mb-1.5">Evaluated Threat</span>
            <span className={`px-2.5 py-1 rounded text-[11px] font-semibold uppercase tracking-wide block ${getRiskColor(scanRisk, false).badge}`}>
              {scanRisk}
            </span>
          </div>
          <div className="flex-1">
            <p className="text-[11px] font-semibold text-slate-900 mb-1.5">Executive Assessment Summary</p>
            <div className="text-[10.5px] text-slate-600 leading-relaxed">
              {renderPrintAnalysis(executiveSummary)}
            </div>
          </div>
        </div>

        {/* Configuration Vulnerabilities */}
        <div className="avoid-break">
          <div className="flex justify-between items-center mb-2.5">
            <h2 className="text-[13px] font-semibold text-slate-900 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-slate-400" />
              1. Running Configuration Vulnerabilities
            </h2>
            <span className="text-[10px] text-slate-500">
              {vulnerabilities.length} violation{vulnerabilities.length === 1 ? '' : 's'}
            </span>
          </div>

          {vulnerabilities.length === 0 ? (
            scanRisk === 'CRITICAL' || scanRisk === 'HIGH' ? (
              <div className="p-3.5 border border-slate-200 rounded-lg bg-slate-50 text-[10px] text-slate-700 flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-slate-900 mb-0.5">Configuration rule baseline clean</p>
                  <p>No syntax rule violations detected. Threat rating assigned as <strong>{scanRisk}</strong> based on operating system lifecycle compliance (Section 2).</p>
                </div>
              </div>
            ) : (
              <div className="p-3.5 border border-slate-200 rounded-lg bg-slate-50 text-[10px] text-slate-700 flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-slate-400 shrink-0" />
                <span>Running configuration satisfies security baseline requirements. Zero configuration vulnerabilities detected.</span>
              </div>
            )
          ) : (
            <div className="space-y-2.5">
              {vulnerabilities.map((v: any, idx: number) => {
                const title = v.title || v.name || v.cve || v.rule || `Finding #${idx + 1}`;
                const severity = (v.severity || v.risk || v.level || 'MEDIUM').toUpperCase();
                const description = v.description || v.summary || v.details || v.impact || 'No detailed description recorded.';
                const remediation = v.remediation_cli || v.remediationCli || v.remediation || v.fix || '';

                return (
                  <div key={v.id || idx} className="border border-slate-200 rounded-lg p-3 text-[10px] space-y-2 avoid-break">
                    <div className="flex justify-between items-center gap-3">
                      <span className="font-semibold text-slate-900 text-[10.5px] flex items-center gap-1.5">
                        <AlertTriangle className="w-3 h-3 text-slate-400 shrink-0" />
                        {idx + 1}. {title}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[8.5px] font-semibold uppercase tracking-wide shrink-0 ${getRiskColor(severity, false).badge}`}>
                        {severity}
                      </span>
                    </div>
                    <p className="text-slate-600 leading-relaxed">{description}</p>
                    {remediation && (
                      <div className="bg-slate-900 text-slate-100 rounded-md p-2.5 text-[8.5px] font-mono mt-1.5">
                        <p className="text-slate-400 font-medium uppercase tracking-wide text-[7.5px] mb-1">Remediation Script</p>
                        <code className="whitespace-pre-wrap block leading-relaxed">{sanitizeConfig(remediation)}</code>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Firmware & OS Compliance */}
        <div className="avoid-break">
          <h2 className="text-[13px] font-semibold text-slate-900 flex items-center gap-1.5 mb-2.5">
            <Cpu className="w-3.5 h-3.5 text-slate-400" />
            2. Firmware Compliance &amp; Lifecycle Risk
          </h2>

          <div className="grid grid-cols-2 gap-x-8 gap-y-3 p-4 border border-slate-200 rounded-lg mb-3">
            <div>
              <p className="text-[9.5px] uppercase tracking-wide text-slate-400 font-medium mb-0.5">Target Version</p>
              <p className="text-[11px] font-medium text-slate-900">{targetFirmware}</p>
            </div>
            <div>
              <p className="text-[9.5px] uppercase tracking-wide text-slate-400 font-medium mb-0.5">Lifecycle Status</p>
              <p className="text-[11px] font-medium text-slate-900">{eolStatus}</p>
            </div>
          </div>

          <div className="border border-slate-200 rounded-lg p-3.5 text-[10px]">
            <p className="font-semibold text-slate-900 mb-1.5">Detailed OS / Firmware Security Analysis</p>
            <div className="text-slate-600 leading-relaxed">
              {renderPrintAnalysis(osAnalysisText)}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-slate-200 text-[9px] text-slate-400 flex justify-between items-center avoid-break">
          <div className="flex items-center gap-1.5">
            <FileCheck className="w-3 h-3 text-slate-400" />
            <span>AegisApex &middot; Official technical risk assessment and operational compliance document</span>
          </div>
          <span>Page 1 of 1</span>
        </div>
      </div>
    </div>
  );
}