//inventorytab.tsx
import React, { useState } from 'react';
import { 
  RefreshCw, 
  FileSpreadsheet, 
  ShieldAlert, 
  Cpu, 
  Search, 
  X
} from 'lucide-react';
import { Device, NavigationTab, AiCacheEntry } from '../_types/dashboard.types';
import { getHighestRisk } from '../_utils/riskHelpers';

interface InventoryTabProps {
  isDarkMode: boolean;
  selectedRiskFilter: string;
  setSelectedRiskFilter: (risk: string) => void;
  filteredDevices: Device[];
  devices: Device[];
  selectedDevice: Device | null;
  setSelectedDevice: (dev: Device) => void;
  setActiveTab: (tab: NavigationTab) => void;
  aiCache: Record<string, AiCacheEntry>;
  isExportingBulk: boolean;
  handleBulkExportPDF: () => void;
}

// Glowing Cyber Pulse Configuration (CrowdStrike / Wiz Style)
const getThreatBadgeConfig = (risk: string, isDark: boolean) => {
  switch (risk?.toUpperCase()) {
    case 'CRITICAL':
      return {
        label: 'CRITICAL',
        dot: 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.9)] animate-pulse',
        badgeStyle: isDark 
          ? 'bg-rose-950/70 border-rose-700/80 text-rose-200' 
          : 'bg-rose-100 border-rose-300 text-rose-900',
      };
    case 'HIGH':
      return {
        label: 'HIGH',
        dot: 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.9)]',
        badgeStyle: isDark 
          ? 'bg-orange-950/70 border-orange-700/80 text-orange-200' 
          : 'bg-orange-100 border-orange-300 text-orange-900',
      };
    case 'MEDIUM':
      return {
        label: 'MEDIUM',
        dot: 'bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.9)]',
        badgeStyle: isDark 
          ? 'bg-amber-950/70 border-amber-700/80 text-amber-200' 
          : 'bg-amber-100 border-amber-300 text-amber-900',
      };
    case 'LOW':
    case 'CLEAN':
      return {
        label: 'LOW',
        dot: 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)]',
        badgeStyle: isDark 
          ? 'bg-emerald-950/70 border-emerald-700/80 text-emerald-200' 
          : 'bg-emerald-100 border-emerald-300 text-emerald-900',
      };
    default:
      return {
        label: 'UNASSESSED',
        dot: 'bg-slate-400',
        badgeStyle: isDark 
          ? 'bg-slate-800/80 border-slate-700 text-slate-300' 
          : 'bg-slate-200 border-slate-300 text-slate-800',
      };
  }
};

export function InventoryTab({
  isDarkMode,
  selectedRiskFilter,
  setSelectedRiskFilter,
  filteredDevices,
  devices,
  selectedDevice,
  setSelectedDevice,
  setActiveTab,
  aiCache,
  isExportingBulk,
  handleBulkExportPDF,
}: InventoryTabProps) {
  const [searchTerm, setSearchTerm] = useState('');

  const threatCounts = devices.reduce(
    (acc, dev) => {
      const devThreat = getHighestRisk(dev.risk_level, aiCache[dev.id]?.riskLevel);
      if (devThreat === 'CRITICAL') acc.critical++;
      else if (devThreat === 'HIGH') acc.high++;
      else if (devThreat === 'MEDIUM') acc.medium++;
      else if (devThreat === 'LOW') acc.low++;
      else acc.unassessed++;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, unassessed: 0 }
  );

  const displayedDevices = filteredDevices.filter((dev) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    const host = (dev.hostname || '').toLowerCase();
    const ip = (dev.ip_address || (dev as any).management_ip || '').toLowerCase();
    const vendor = (dev.vendor || '').toLowerCase();
    return host.includes(term) || ip.includes(term) || vendor.includes(term);
  });

  const metricCardClass = (active: boolean) =>
    `p-3.5 rounded-xl border transition-all duration-200 cursor-pointer flex flex-col justify-between select-none relative ${
      active
        ? isDarkMode
          ? 'bg-slate-800 border-slate-600'
          : 'bg-white border-slate-900 shadow-xs'
        : isDarkMode
        ? 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/60 hover:border-slate-700'
        : 'bg-white border-slate-200 hover:border-slate-300 hover:shadow-xs'
    }`;

  return (
    <div className="space-y-4">
      {/* Fleet Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <div onClick={() => setSelectedRiskFilter('ALL')} className={metricCardClass(selectedRiskFilter === 'ALL')}>
          <span className={`text-xs uppercase tracking-wider font-extrabold ${isDarkMode ? 'text-slate-300' : 'text-slate-800'}`}>
            Total Fleet
          </span>
          <div className={`text-2xl font-black my-1 font-mono tracking-tight ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>{devices.length}</div>
          <span className={`text-[11px] font-medium ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            Monitored Assets
          </span>
        </div>

        <div onClick={() => setSelectedRiskFilter('CRITICAL')} className={metricCardClass(selectedRiskFilter === 'CRITICAL')}>
          <span className={`text-xs uppercase tracking-wider font-extrabold ${isDarkMode ? 'text-rose-400' : 'text-rose-800'}`}>
            Critical
          </span>
          <div className="text-2xl font-black my-1 font-mono tracking-tight text-rose-500">{threatCounts.critical}</div>
          <span className={`text-[11px] font-medium ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            Action Required
          </span>
        </div>

        <div onClick={() => setSelectedRiskFilter('HIGH')} className={metricCardClass(selectedRiskFilter === 'HIGH')}>
          <span className={`text-xs uppercase tracking-wider font-extrabold ${isDarkMode ? 'text-orange-400' : 'text-orange-800'}`}>
            High Severity
          </span>
          <div className="text-2xl font-black my-1 font-mono tracking-tight text-orange-500">{threatCounts.high}</div>
          <span className={`text-[11px] font-medium ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            Elevated Risk
          </span>
        </div>

        <div onClick={() => setSelectedRiskFilter('MEDIUM')} className={metricCardClass(selectedRiskFilter === 'MEDIUM')}>
          <span className={`text-xs uppercase tracking-wider font-extrabold ${isDarkMode ? 'text-amber-400' : 'text-amber-800'}`}>
            Medium Risk
          </span>
          <div className="text-2xl font-black my-1 font-mono tracking-tight text-amber-500">{threatCounts.medium}</div>
          <span className={`text-[11px] font-medium ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            Policy Drift
          </span>
        </div>

        <div onClick={() => setSelectedRiskFilter('LOW')} className={metricCardClass(selectedRiskFilter === 'LOW')}>
          <span className={`text-xs uppercase tracking-wider font-extrabold ${isDarkMode ? 'text-emerald-400' : 'text-emerald-800'}`}>
            Low / Clean
          </span>
          <div className="text-2xl font-black my-1 font-mono tracking-tight text-emerald-500">{threatCounts.low}</div>
          <span className={`text-[11px] font-medium ${isDarkMode ? 'text-slate-400' : 'text-slate-500 me-0'}`}>
            Hardened Baseline
          </span>
        </div>
      </div>

      {/* Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-end gap-3 pt-1">
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Bar */}
          <div
            className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-xs transition-all w-56 ${
              isDarkMode
                ? 'bg-slate-900 border-slate-800 focus-within:border-slate-600'
                : 'bg-white border-slate-300 focus-within:border-slate-900'
            }`}
          >
            <Search className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <input
              type="text"
              placeholder="Search hostname or IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className={`w-full bg-transparent outline-none font-mono text-xs placeholder:font-sans placeholder:text-slate-500 ${
                isDarkMode ? 'text-slate-100' : 'text-slate-900'
              }`}
            />
            {searchTerm && (
              <button onClick={() => setSearchTerm('')} className="text-slate-400 hover:text-slate-200">
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Export Button */}
          <button
            onClick={handleBulkExportPDF}
            disabled={isExportingBulk || displayedDevices.length === 0}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-normal border transition-all cursor-pointer disabled:opacity-50 active:scale-95 ${
              isDarkMode
                ? 'bg-slate-900 hover:bg-slate-800 text-slate-200 border-slate-800 hover:border-slate-700'
                : 'bg-white hover:bg-slate-50 text-slate-800 border-slate-300 shadow-xs'
            }`}
          >
            {isExportingBulk ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-slate-400" />
            ) : (
              <FileSpreadsheet className={`w-3.5 h-3.5 ${isDarkMode ? 'text-slate-300' : 'text-slate-700'}`} />
            )}
            <span>
              {isExportingBulk
                ? 'Exporting...'
                : `Export Report (${selectedRiskFilter === 'ALL' ? 'Fleet' : selectedRiskFilter})`}
            </span>
          </button>
        </div>
      </div>

      {/* Table Canvas */}
      <div
        className={`rounded-xl border transition-all overflow-hidden ${
          isDarkMode
            ? 'bg-slate-900/40 border-slate-800'
            : 'bg-white border-slate-200 shadow-xs'
        }`}
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left min-w-[740px] border-collapse">
            <thead
              className={`font-mono text-xs tracking-wider uppercase border-b select-none ${
                isDarkMode
                  ? 'bg-slate-800/60 border-slate-800 text-slate-400 font-bold'
                  : 'bg-slate-100/70 border-slate-200 text-slate-600 font-bold'
              }`}
            >
              <tr>
                <th className="py-3 pl-3 pr-1 w-6 text-center"></th>
                <th className="py-3 font-semibold px-3">Device Hostname</th>
                <th className="py-3 font-semibold px-4">Management IP</th>
                <th className="py-3 font-semibold px-4">Vendor & Platform</th>
                <th className="py-3 font-semibold px-4">Domain / Supplier</th>
                <th className="py-3 font-bold px-4 text-left">Threat State</th>
                <th className="py-3 font-semibold px-4 text-right">Quick Inspection</th>
              </tr>
            </thead>
            <tbody className={`divide-y ${isDarkMode ? 'divide-slate-800/80' : 'divide-slate-200'}`}>
              {displayedDevices.length === 0 ? (
                <tr>
                  <td colSpan={7} className={`text-center py-8 font-sans text-xs ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>
                    {searchTerm
                      ? `No assets match search term "${searchTerm}".`
                      : `No managed network assets match risk filter "${selectedRiskFilter}".`}
                  </td>
                </tr>
              ) : (
                displayedDevices.map((dev) => {
                  const isSelected = selectedDevice?.id === dev.id;
                  const devThreat = getHighestRisk(dev.risk_level, aiCache[dev.id]?.riskLevel);
                  const threatConfig = getThreatBadgeConfig(devThreat, isDarkMode);

                  const displayIp = dev.ip_address || (dev as any).management_ip || 'N/A';
                  const platformType = dev.netmiko_type || (dev as any).device_type || 'N/A';
                  const supplierName = dev.suppliers?.name || (dev as any).supplier?.name || 'Internal Ops';

                  return (
                    <tr
                      key={dev.id}
                      onClick={() => setSelectedDevice(dev)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? isDarkMode
                            ? 'bg-slate-800/90 text-white'
                            : 'bg-slate-100 text-slate-900'
                          : isDarkMode
                          ? 'text-slate-300 hover:bg-slate-800/50'
                          : 'text-slate-700 hover:bg-slate-50'
                      }`}
                    >
                      {/* Selection Indicator */}
                      <td className="py-3 pl-3 pr-1 text-center w-6">
                        <div className="flex items-center justify-center">
                          <div
                            className={`w-1 h-4 rounded-full transition-all ${
                              isSelected
                                ? isDarkMode
                                  ? 'bg-slate-200'
                                  : 'bg-slate-900'
                                : 'bg-transparent'
                            }`}
                          />
                        </div>
                      </td>

                      {/* Device Hostname */}
                      <td className="py-3 px-3 text-left">
                        <span className={`font-mono text-sm font-semibold tracking-tight truncate block ${
                          isSelected
                            ? isDarkMode ? 'text-white' : 'text-slate-950'
                            : isDarkMode ? 'text-slate-100' : 'text-slate-900'
                        }`}>
                          {dev.hostname}
                        </span>
                      </td>

                      {/* Management IP */}
                      <td className={`py-3 px-4 text-left font-mono text-xs font-normal ${
                        isDarkMode ? 'text-slate-300' : 'text-slate-700'
                      }`}>
                        {displayIp}
                      </td>

                      {/* Vendor & Platform */}
                      <td className={`py-3 px-4 text-left uppercase text-xs font-mono font-normal ${
                        isDarkMode ? 'text-slate-300' : 'text-slate-700'
                      }`}>
                        {dev.vendor || 'Generic'} ({platformType})
                      </td>

                      {/* Supplier */}
                      <td className={`py-3 px-4 text-left font-sans text-xs font-normal ${
                        isDarkMode ? 'text-slate-300' : 'text-slate-700'
                      }`}>
                        {supplierName}
                      </td>

                      {/* Glowing Cyber Pulse Badge with Bold Font Weight */}
                      <td className="py-3 px-4 text-left">
                        <div className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-full border font-mono text-[11px] font-black tracking-wider ${threatConfig.badgeStyle}`}>
                          <span className={`w-2 h-2 rounded-full shrink-0 ${threatConfig.dot}`} />
                          <span className="font-black">{threatConfig.label}</span>
                        </div>
                      </td>

                      {/* Quick Inspection Buttons */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => {
                              setSelectedDevice(dev);
                              setActiveTab('config');
                            }}
                            className={`px-2.5 py-1 rounded text-xs font-sans transition-all cursor-pointer border flex items-center gap-1 active:scale-95 ${
                              isDarkMode
                                ? 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                                : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300 shadow-xs'
                            }`}
                          >
                            <ShieldAlert className={`w-3.5 h-3.5 ${isDarkMode ? 'text-purple-400' : 'text-purple-800'}`} />
                            <span className="font-medium">Config</span>
                          </button>
                          <button
                            onClick={() => {
                              setSelectedDevice(dev);
                              setActiveTab('version');
                            }}
                            className={`px-2.5 py-1 rounded text-xs font-sans transition-all cursor-pointer border flex items-center gap-1 active:scale-95 ${
                              isDarkMode
                                ? 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                                : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300 shadow-xs'
                            }`}
                          >
                            <Cpu className={`w-3.5 h-3.5 ${isDarkMode ? 'text-blue-400' : 'text-blue-600'}`} />
                            <span className="font-medium">Version</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}