//  C:\Users\hp\aiops-securewatch\dashboard\_components\ConfigTab.tsx
// C:\Users\hp\aiops-securewatch\dashboard\_components\ConfigTab.tsx
import React, { useMemo } from 'react';
import { Code2, ShieldAlert, Shield } from 'lucide-react';
import { sanitizeConfig } from '@/lib/sanitizer';
import { Device, ScanResult, AiCacheEntry, Vulnerability } from '../_types/dashboard.types';
import { getRiskColor } from '../_utils/riskHelpers';
import { renderFormattedAnalysis } from '../_utils/formatters';

interface ConfigTabProps {
  isDarkMode: boolean;
  selectedDevice: Device | null;
  currentRawConfig: string;
  activeDeviceRisk: string;
  aiCache: Record<string, AiCacheEntry>;
  latestScan: ScanResult | null;
}

export function ConfigTab({
  isDarkMode,
  selectedDevice,
  currentRawConfig,
  activeDeviceRisk,
  aiCache,
  latestScan,
}: ConfigTabProps) {
  const displayConfig = useMemo(() => {
    const rawCandidate =
      currentRawConfig && currentRawConfig.trim() !== '!'
        ? currentRawConfig
        : selectedDevice?.last_config || (selectedDevice as any)?.config || '';

    const trimmed = rawCandidate.trim();
    if (!trimmed || trimmed === '!') return '';

    return sanitizeConfig(trimmed);
  }, [currentRawConfig, selectedDevice]);

  const sessionAnalysis = selectedDevice?.id ? aiCache[selectedDevice.id]?.config : null;
  const persistedAnalysis = latestScan?.summary || (latestScan as any)?.executive_summary;
  const configSummaryToRender = sessionAnalysis || persistedAnalysis;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Active Configuration Terminal Viewer */}
      <div
        className={`rounded-xl border flex flex-col h-[650px] ${
          isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
        }`}
      >
        <div
          className={`p-3.5 border-b flex items-center justify-between ${
            isDarkMode ? 'border-slate-800 bg-slate-950/40' : 'border-slate-200 bg-slate-50'
          }`}
        >
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-purple-400" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              Sanitized Active Configuration
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            {selectedDevice?.hostname || 'Select Target'}
          </span>
        </div>

        <div
          className={`flex-1 p-4 overflow-y-auto font-mono text-xs leading-relaxed rounded-b-xl border-t [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:rounded-full ${
            isDarkMode
              ? 'bg-slate-950 text-slate-300 border-slate-900 [&::-webkit-scrollbar-thumb]:bg-slate-700'
              : 'bg-slate-50 text-slate-800 border-slate-200 [&::-webkit-scrollbar-thumb]:bg-slate-300'
          }`}
        >
          {displayConfig ? (
            <pre className="whitespace-pre-wrap break-all">{displayConfig}</pre>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 text-center p-6 space-y-2">
              <Code2 className="w-8 h-8 text-slate-600 mb-1" />
              <p className="font-semibold text-slate-400 text-xs">
                No Running Configuration Telemetry Available
              </p>
              <p className="text-[11px] text-slate-500 max-w-sm">
                Click <strong className="text-purple-400 font-bold">"Scan Inventory"</strong> to capture device configuration.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Audit Findings & Remediation View */}
      <div
        className={`rounded-xl border p-5 flex flex-col h-[650px] overflow-hidden ${
          isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
        }`}
      >
        <div
          className={`flex items-center justify-between pb-3 border-b mb-4 shrink-0 ${
            isDarkMode ? 'border-slate-800' : 'border-slate-200'
          }`}
        >
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
            <h3 className="font-bold text-sm">Security Findings & Hardening</h3>
          </div>
          {activeDeviceRisk && (
            <span
              className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border uppercase tracking-wider ${
                getRiskColor(activeDeviceRisk, isDarkMode).badge
              }`}
            >
              {activeDeviceRisk}
            </span>
          )}
        </div>

        <div
          className={`flex-1 overflow-y-auto space-y-3 pr-1 [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:rounded-full ${
            isDarkMode ? '[&::-webkit-scrollbar-thumb]:bg-slate-700' : '[&::-webkit-scrollbar-thumb]:bg-slate-300'
          }`}
        >
          {/* Priority 1: Active session AI cache analysis */}
          {sessionAnalysis ? (
            <div className="p-2">
              {renderFormattedAnalysis(sessionAnalysis, isDarkMode)}
            </div>
          ) : latestScan?.vulnerabilities && latestScan.vulnerabilities.length > 0 ? (
            /* Priority 2: Structured static CIS benchmark vulnerabilities (unchanged) */
            latestScan.vulnerabilities.map((v: Vulnerability, idx: number) => {
              const vRisk = getRiskColor(v.severity, isDarkMode);
              const remediation = v.remediation_cli || (v as any).remediationCli || '';

              return (
                <div
                  key={v.id || `${v.title}-${idx}`}
                  className={`p-3.5 rounded-lg border text-xs space-y-2 border-l-4 ${vRisk.accent} ${
                    isDarkMode ? 'bg-slate-950/80 border-slate-800' : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span
                      className={`font-bold ${
                        isDarkMode ? 'text-slate-100' : 'text-slate-800'
                      }`}
                    >
                      {v.title}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase border shrink-0 ${vRisk.badge}`}
                    >
                      {v.severity}
                    </span>
                  </div>

                  <p
                    className={`text-[11px] leading-relaxed ${
                      isDarkMode ? 'text-slate-400' : 'text-slate-600'
                    }`}
                  >
                    {v.description}
                  </p>

                  {remediation && (
                    <div
                      className={`mt-2 p-2 border rounded font-mono text-[10px] ${
                        isDarkMode
                          ? 'bg-slate-900 border-slate-800'
                          : 'bg-slate-100 border-slate-300'
                      }`}
                    >
                      <span className="text-slate-500 uppercase font-bold block mb-1">
                        Remediation CLI:
                      </span>
                      <code className="text-emerald-500 font-bold block whitespace-pre-wrap">
                        {sanitizeConfig(remediation)}
                      </code>
                    </div>
                  )}
                </div>
              );
            })
          ) : persistedAnalysis ? (
            <div className="p-2">
              {renderFormattedAnalysis(persistedAnalysis, isDarkMode)}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 text-center p-6 space-y-2">
              <Shield className="w-8 h-8 text-slate-600 mb-1" />
              <p className="font-semibold text-slate-400 text-xs">
                No Active AI Audit Results
              </p>

            </div>
          )}
        </div>
      </div>
    </div>
  );
}