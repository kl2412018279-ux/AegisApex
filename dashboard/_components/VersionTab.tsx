// dashboard\_components\VersionTab.tsx
import React from 'react';
import { Cpu, Sparkles, Loader2 } from 'lucide-react';
import { Device, ScanResult, AiCacheEntry } from '../_types/dashboard.types';
import { getRiskColor } from '../_utils/riskHelpers';
import { renderFormattedAnalysis } from '../_utils/formatters';
// FIX: this file used to run its own tiny ad-hoc vendor check
// (`vendorStr.includes('cisco')` etc., covering only cisco/aruba/dell) as
// its last-resort guess for a never-analyzed device. That's the same
// vendor-detection duplication problem fixed in analyze-firmware/route.ts —
// now this file uses the one real detectVendor() too, so "never analyzed
// yet" devices on any of the 16 platforms cisBenchmarks.ts knows about get
// a sensible vendor-specific placeholder instead of all non-Cisco/Aruba/Dell
// vendors (Fortinet included) falling into one generic "Vendor Secure
// Baseline" bucket.
import { detectVendor, VendorType } from '../lib/cisBenchmarks';

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

// NEW: this is purely a DISPLAY placeholder for a device that has never
// been through /api/analyze-firmware at all yet (latestScan.target_firmware
// is empty and the cached AI text, if any, doesn't contain an explicit
// upgrade-version phrase). It only ever needs to look plausible until the
// person clicks "Re-analyze Firmware" / "Run AI Assessment" once — the real
// value always comes from the AI afterward. Kept intentionally lighter than
// the backend's VENDOR_FALLBACK_MATRIX (no CVEs/recommendations needed
// here, just a name + lifecycle guess per platform).
const VENDOR_BASELINE_DISPLAY: Record<VendorType, { target: string; eol: string }> = {
  cisco_ios: { target: 'Cisco IOS-XE 17.09.05 LTS', eol: 'Active / Supported' },
  cisco_nxos: { target: 'Cisco NX-OS 10.3(x) LTS', eol: 'Active / Supported' },
  cisco_xr: { target: 'Cisco IOS-XR 7.9.x LTS', eol: 'Active / Supported' },
  juniper: { target: 'Junos 21.4 EEOL', eol: 'Active / Supported' },
  arista: { target: 'Arista EOS 4.31.x', eol: 'Active / Supported' },
  fortinet: { target: 'FortiOS 7.4.x LTS', eol: 'Active / Supported' },
  paloalto: { target: 'PAN-OS 11.1.x', eol: 'Active / Supported' },
  huawei: { target: 'Huawei VRP 8.x (current maintenance release)', eol: 'Active / Supported' },
  aruba_hpe: { target: 'ArubaOS-CX 10.13.1000 LTS', eol: 'Active / Supported' },
  dell_os10: { target: 'Dell OS10 10.5.6.0', eol: 'Active / Supported' },
  f5_tmsh: { target: 'F5 BIG-IP TMOS 17.1.x', eol: 'Active / Supported' },
  nokia_sros: { target: 'Nokia SR OS 23.x', eol: 'Active / Supported' },
  vyos: { target: 'VyOS 1.4 LTS', eol: 'Active / Supported' },
  extreme_exos: { target: 'Extreme EXOS 32.x', eol: 'Active / Supported' },
  mikrotik: { target: 'MikroTik RouterOS 7.x (stable channel)', eol: 'Active / Supported' },
  generic: { target: 'Unable to determine (unidentified platform)', eol: 'Unknown — verify with vendor' },
};

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

  // FIX: useDashboard.ts's fetchScanResults() defaults target_firmware/
  // eol_status to the literal string "Not yet analyzed" whenever a scan
  // row doesn't have them persisted yet (e.g. a brand-new device's very
  // first scan). That string is non-empty, so the plain `!target` / `!eol`
  // checks below treated it as "already have a real answer" and skipped
  // straight past the bullet-extraction fix — displaying "Not yet
  // analyzed" in the hero cards even while the AI analysis panel right
  // next to it showed the real, already-computed answer. Treat this
  // sentinel (and plain emptiness) the same way: as "nothing resolved
  // yet", so the extraction below actually runs.
  const isUnresolvedPlaceholder = (v: string | null | undefined): boolean =>
    !v || v.trim().toLowerCase() === 'not yet analyzed';

  // Dynamic metric extraction from AI output + device metadata
  const deriveFirmwareMetrics = () => {
    let target = latestScan?.target_firmware || (latestScan as any)?.recommended_version;
    let eol = latestScan?.eol_status || (latestScan as any)?.eolStatus;
    if (isUnresolvedPlaceholder(target)) target = undefined;
    if (isUnresolvedPlaceholder(eol)) eol = undefined;

    if (osSummaryToRender) {
      // FIX: both checks below used to scan the whole free-form AI narrative
      // with loose keyword regexes. That's what produced a real bug: the
      // AI's own executive summary for an EOL Palo Alto device read
      // "Immediate upgrade to a supported release is required" — the old
      // EOL regex matched the bare word "supported" in that sentence and
      // displayed "Active / Supported" for a device the same screen's AI
      // analysis correctly labeled "End-of-Life (EOL)" one panel over. The
      // AI's own response already includes unambiguous, explicitly-labeled
      // bullet lines ("▸ Lifecycle Support Status: ...", "▸ Recommended LTS
      // Release: ...") produced by the backend's formattedMarkdownSummary —
      // we now parse those directly first, and only fall back to the old
      // loose keyword guesses if a bullet line isn't present (e.g. an older
      // cached analysis saved before this format existed).

      // 1. Lifecycle support detection — prefer the AI's own labeled bullet.
      if (!eol) {
        const eolBulletMatch = osSummaryToRender.match(/Lifecycle Support Status:\s*([^\n▸]+)/i);
        if (eolBulletMatch) {
          eol = eolBulletMatch[1].trim();
        } else if (/eol|eos|end[\s-]?of[\s-]?life|end[\s-]?of[\s-]?support|deprecated/i.test(osSummaryToRender)) {
          eol = 'End-of-Life (EOL)';
        } else if (/not yet eol\/eos|mainstream|active support/i.test(osSummaryToRender)) {
          eol = 'Active / Supported';
        }
      }

      // 2. Target OS version — prefer the AI's own labeled bullet.
      if (!target || target.toLowerCase().includes('recommended') || target.toLowerCase().includes('latest')) {
        const targetBulletMatch = osSummaryToRender.match(/Recommended LTS Release:\s*([^\n▸]+)/i);
        if (targetBulletMatch) {
          target = targetBulletMatch[1].trim();
        } else {
          const explicitMatch = osSummaryToRender.match(/(?:upgrade|target|recommended|latest)\s+(?:to\s+)?([A-Za-z0-9_.-]+\s+[0-9]+\.[0-9]+[A-Za-z0-9_.-]*)/i);
          if (explicitMatch) {
            target = explicitMatch[1];
          }
        }
      }
    }

    // 3. Hardware Vendor Baseline Fallbacks
    // FIX: replaced the old 3-vendor `.includes()` chain (cisco/aruba/dell
    // only, everything else incl. fortinet => generic "Vendor Secure
    // Baseline") with the same detectVendor() used everywhere else in the
    // system, plus a lookup table covering all 16 platforms.
    if (!target || target.toLowerCase().includes('recommended') || target.toLowerCase().includes('latest')) {
      const vendorStr = `${selectedDevice?.vendor || ''} ${selectedDevice?.netmiko_type || ''} ${currentRawVersion}`.toLowerCase();
      const vendorType = detectVendor(vendorStr);
      target = VENDOR_BASELINE_DISPLAY[vendorType].target;
    }

    if (!eol) {
      const vendorStr = `${selectedDevice?.vendor || ''} ${selectedDevice?.netmiko_type || ''} ${currentRawVersion}`.toLowerCase();
      const vendorType = detectVendor(vendorStr);
      eol = VENDOR_BASELINE_DISPLAY[vendorType].eol;
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

          <div
            className={`flex-1 p-4 overflow-y-auto font-mono text-xs leading-relaxed rounded-b-xl border-t ${
              isDarkMode
                ? 'bg-slate-950 text-slate-300 border-slate-900'
                : 'bg-slate-50 text-slate-800 border-slate-200'
            }`}
          >
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