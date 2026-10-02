// dashboard\_components\VersionTab.tsx
import React from 'react';
import { Cpu, Sparkles, Loader2 } from 'lucide-react';
import { Device, ScanResult, AiCacheEntry } from '../_types/dashboard.types';
import { getRiskColor } from '../_utils/riskHelpers';
import { renderFormattedAnalysis } from '../_utils/formatters';

interface VersionTabProps {
  isDarkMode: boolean;
  selectedDevice: Device | null;
  latestScan: ScanResult | null;
  activeDeviceRisk: string;
  currentRawVersion: string;
  currentOsSummary: string;
  aiCache: Record<string, AiCacheEntry>;
  handleAnalyzeFirmware: () => void;
  isScanning?: boolean;
}

export function VersionTab({
  isDarkMode,
  selectedDevice,
  latestScan,
  activeDeviceRisk,
  currentRawVersion,
  currentOsSummary,
  aiCache,
  handleAnalyzeFirmware,
  isScanning = false,
}: VersionTabProps) {
  // Resolve active AI analysis text
  const cachedAnalysis = selectedDevice?.id ? aiCache[selectedDevice.id]?.firmware : null;
  const osSummaryToRender = cachedAnalysis || currentOsSummary;

  // Dynamic metric extraction from AI output + device metadata
  const deriveFirmwareMetrics = () => {
    let target = latestScan?.target_firmware || (latestScan as any)?.recommended_version;
    let eol = latestScan?.eol_status || (latestScan as any)?.eolStatus;

    if (osSummaryToRender) {
      // 1. Lifecycle support detection
      if (!eol) {
        if (/not yet eol\/eos|mainstream|active support|supported/i.test(osSummaryToRender)) {
          eol = 'Active / Supported';
        } else if (/eol|eos|end of life|end of support|deprecated/i.test(osSummaryToRender)) {
          eol = 'End-of-Life (EOL)';
        }
      }

      // 2. Target OS version regex matching
      if (!target || target.toLowerCase().includes('recommended') || target.toLowerCase().includes('latest')) {
        const explicitMatch = osSummaryToRender.match(/(?:upgrade|target|recommended|latest)\s+(?:to\s+)?([A-Za-z0-9_.-]+\s+[0-9]+\.[0-9]+[A-Za-z0-9_.-]*)/i);
        if (explicitMatch) {
          target = explicitMatch[1];
        }
      }
    }

    // 3. Hardware Vendor Baseline Fallbacks
    if (!target || target.toLowerCase().includes('recommended') || target.toLowerCase().includes('latest')) {
      const vendorStr = `${selectedDevice?.vendor || ''} ${selectedDevice?.netmiko_type || ''} ${currentRawVersion}`.toLowerCase();
      if (vendorStr.includes('aruba') || vendorStr.includes('aoscx')) {
        target = 'ArubaOS-CX 10.13.1000 LTS';
      } else if (vendorStr.includes('cisco')) {
        target = 'Cisco IOS-XE 17.09.05 LTS';
      } else if (vendorStr.includes('dell')) {
        target = 'Dell OS10 10.5.6.0';
      } else {
        target = 'Vendor Secure Baseline';
      }
    }

    if (!eol) {
      eol = 'Mainstream Active';
    }

    return { targetFirmware: target, eolStatus: eol };
  };

  const { targetFirmware, eolStatus } = deriveFirmwareMetrics();

  const cardStyle = `p-4 rounded-xl border flex flex-col justify-between ${
    isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
  }`;

  return (
    <div className="space-y-6">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={cardStyle}>
          <span className="text-xs font-mono text-slate-400 uppercase font-bold">
            Recommended LTS Release
          </span>
          <div className="text-lg font-bold text-emerald-400 my-1 font-mono truncate">
            {targetFirmware}
          </div>
          <p className="text-[11px] text-slate-500">
            Target secure baseline image for this hardware profile.
          </p>
        </div>

        <div className={cardStyle}>
          <span className="text-xs font-mono text-slate-400 uppercase font-bold">
            Lifecycle Support Status
          </span>
          <div className="text-lg font-bold text-blue-400 my-1 font-mono truncate">
            {eolStatus}
          </div>
          <p className="text-[11px] text-slate-500">
            Vendor technical support and security patch lifecycle state.
          </p>
        </div>

        <div className={cardStyle}>
          <span className="text-xs font-mono text-slate-400 uppercase font-bold">
            Normalized Threat Level
          </span>
          <div className="flex items-center gap-2 my-1">
            <span
              className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border uppercase tracking-wider ${
                getRiskColor(activeDeviceRisk, isDarkMode).badge
              }`}
            >
              {activeDeviceRisk || 'EVALUATED'}
            </span>
          </div>
          <p className="text-[11px] text-slate-500">
            Maximum threat level normalized across configuration & OS firmware scans.
          </p>
        </div>
      </div>

      {/* Main Split Telemetry & AI View */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Raw Version Telemetry Panel */}
        <div
          className={`rounded-xl border flex flex-col h-[550px] ${
            isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
          }`}
        >
          <div
            className={`p-3.5 border-b flex items-center justify-between ${
              isDarkMode ? 'border-slate-800 bg-slate-950/40' : 'border-slate-200 bg-slate-50'
            }`}
          >
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-blue-400" />
              <span className={`font-mono text-xs font-bold uppercase ${
                isDarkMode ? 'text-slate-300' : 'text-slate-700'
              }`}>
                Collected Version Telemetry
              </span>
            </div>
            <button
              onClick={handleAnalyzeFirmware}
              disabled={!selectedDevice || !currentRawVersion.trim() || isScanning}
              className="px-2.5 py-1 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed text-white rounded text-[11px] font-sans font-bold transition-all cursor-pointer shadow-sm flex items-center gap-1.5"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-3 h-3 animate-spin text-white" />
                  Analyzing...
                </>
              ) : (
                'Re-analyze Firmware'
              )}
            </button>
          </div>

          <div className="flex-1 p-4 overflow-y-auto font-mono text-xs bg-slate-950 text-slate-300 leading-relaxed rounded-b-xl border-t border-slate-900">
            {currentRawVersion.trim() ? (
              <pre className="whitespace-pre-wrap break-words">{currentRawVersion}</pre>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-center p-6 space-y-2">
                <Cpu className="w-8 h-8 text-slate-600 mb-1" />
                <p className="font-semibold text-slate-400 text-xs">No OS Version Telemetry Available</p>
                <p className="text-[11px] text-slate-500 max-w-sm">
                  Click <strong className="text-blue-400 font-bold">"📡 Collect Telemetry"</strong> to poll device OS version information.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* AI OS Security Analysis Panel */}
        <div
          className={`rounded-xl border p-5 flex flex-col h-[550px] overflow-hidden ${
            isDarkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
          }`}
        >
          <div className={`flex items-center justify-between pb-3 border-b mb-4 shrink-0 ${
            isDarkMode ? 'border-slate-800' : 'border-slate-200'
          }`}>
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-blue-400" />
              <h3 className="font-bold text-sm">AI OS Security Analysis</h3>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto space-y-3 pr-1">
            {osSummaryToRender ? (
              <div className="p-2">
                {renderFormattedAnalysis(osSummaryToRender, isDarkMode)}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-center p-6 space-y-2">
                <Cpu className="w-8 h-8 text-slate-600 mb-1" />
                <p className="font-semibold text-slate-400 text-xs">No Firmware Assessment Generated</p>
                <p className="text-[11px] text-slate-500 max-w-sm">
                  Click <strong className="text-blue-400 font-bold">"Re-analyze Firmware"</strong> or <strong className="text-emerald-400 font-bold">"🤖 Run AI Assessment"</strong>.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}