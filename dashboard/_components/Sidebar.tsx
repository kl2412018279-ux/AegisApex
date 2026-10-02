// dashboard/_components/Sidebar.tsx
import React from 'react';
import {
  ShieldAlert,
  Server,
  Sparkles,
  FileText,
  Cpu,
  Terminal as TerminalIcon,
  RefreshCw,
  Layers,
} from 'lucide-react';
import { NavigationTab, Device } from '../_types/dashboard.types';

interface ExtendedDevice extends Device {
  management_ip?: string;
}

interface SidebarProps {
  isDarkMode: boolean;
  activeTab: NavigationTab;
  setActiveTab: (tab: NavigationTab) => void;
  selectedDevice: Device | null;
  isScanning: boolean;
  isScanningAll: boolean;
  scanProgress: { current: number; total: number };
  devicesLength: number;
  handleCollectTelemetry: () => void;
  handleRunScan: () => void;
  handleScanAll: () => void;
}

const NAV_ITEMS: { id: NavigationTab; label: string; icon: React.ElementType; color: string }[] = [
  { id: 'inventory', label: 'Inventory', icon: Server, color: 'text-emerald-500 dark:text-emerald-400' },
  { id: 'config', label: 'show running-config', icon: FileText, color: 'text-purple-500 dark:text-purple-400' },
  { id: 'version', label: 'show version & OS', icon: Cpu, color: 'text-blue-500 dark:text-blue-400' },
  { id: 'sandbox', label: 'Impact Sandbox', icon: TerminalIcon, color: 'text-amber-500 dark:text-amber-400' },
];

export function Sidebar({
  isDarkMode,
  activeTab,
  setActiveTab,
  selectedDevice,
  isScanning,
  isScanningAll,
  scanProgress,
  devicesLength,
  handleCollectTelemetry,
  handleRunScan,
  handleScanAll,
}: SidebarProps) {
  const extDevice = selectedDevice as ExtendedDevice | null;
  const displayIp = extDevice?.ip_address || extDevice?.management_ip || '0.0.0.0';

  const total = scanProgress?.total || 1;
  const current = scanProgress?.current || 0;
  const progressPercent = Math.min(100, Math.round((current / total) * 100));

  return (
    <aside
      className={`w-64 flex flex-col justify-between shrink-0 border-r transition-colors duration-200 select-none ${
        isDarkMode
          ? 'bg-slate-900 border-slate-800 text-slate-300'
          : 'bg-slate-50/50 border-slate-300/80 text-slate-700 shadow-sm'
      }`}
    >
      <div>
        {/* App Title Header */}
        <div
          className={`p-5 border-b flex items-center justify-between ${
            isDarkMode ? 'border-slate-800 bg-slate-900' : 'border-slate-200 bg-white'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg border shrink-0 ${
                isDarkMode
                  ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                  : 'bg-emerald-100/70 border-emerald-300 text-emerald-700'
              }`}
            >
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h1
                className={`font-bold text-sm tracking-tight leading-tight ${
                  isDarkMode ? 'text-white' : 'text-slate-900'
                }`}
              >
                AegisApex
              </h1>
              <p
                className={`text-[10px] font-mono mt-0.5 ${
                  isDarkMode ? 'text-slate-400' : 'text-slate-500'
                }`}
              >
                
              </p>
            </div>
          </div>
        </div>

        {/* Selected Active Target Banner */}
        {selectedDevice && (
          <div
            className={`m-3 p-3 rounded-lg text-xs font-mono border transition-all ${
              isDarkMode
                ? 'bg-slate-950/80 border-slate-800 text-slate-300 shadow-inner'
                : 'bg-white border-slate-300 text-slate-800 shadow-sm ring-1 ring-slate-200/60'
            }`}
          >
            <div className="flex justify-between items-center mb-1">
              <span className="text-[9px] uppercase tracking-wider font-bold text-slate-500">
                Target
              </span>
            </div>
            <div
              className={`text-xs font-mono font-bold truncate ${
                isDarkMode ? 'text-white' : 'text-slate-900'
              }`}
            >
              {selectedDevice.hostname || 'Unknown Host'}{' '}
              <span className={isDarkMode ? 'text-slate-400' : 'text-slate-500'}>
                ({displayIp})
              </span>
            </div>
          </div>
        )}

        {/* Dynamic Navigation */}
        <nav className="p-3 space-y-1.5">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-semibold transition-all cursor-pointer border ${
                  isActive
                    ? isDarkMode
                      ? 'bg-slate-800 text-white border-slate-700 shadow-sm'
                      : 'bg-white text-emerald-800 border-emerald-400 shadow-md ring-1 ring-emerald-400/30'
                    : isDarkMode
                    ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border-transparent'
                    : 'bg-white/80 text-slate-700 hover:text-slate-900 hover:bg-white border-slate-200/90 shadow-xs'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${item.color}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Action Footer Panel */}
      <div
        className={`p-3 border-t space-y-2.5 ${
          isDarkMode
            ? 'border-slate-800 bg-slate-900'
            : 'border-slate-300/80 bg-slate-100/70'
        }`}
      >
        {isScanningAll && (
          <div
            className={`mb-2 p-2 rounded border text-[10px] font-mono shadow-xs ${
              isDarkMode
                ? 'bg-slate-950 border-slate-800 text-slate-400'
                : 'bg-white border-slate-300 text-slate-700'
            }`}
          >
            <div className="flex justify-between mb-1 font-bold">
              <span>Scanning Inventory...</span>
              <span>
                {current}/{total} ({progressPercent}%)
              </span>
            </div>
            <div
              className={`w-full h-1.5 rounded-full overflow-hidden ${
                isDarkMode ? 'bg-slate-800' : 'bg-slate-200'
              }`}
            >
              <div
                className="bg-emerald-500 h-full transition-all duration-300"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>
        )}

        <button
          onClick={handleCollectTelemetry}
          disabled={isScanning || isScanningAll || !selectedDevice}
          className={`w-full flex items-center justify-center gap-2 px-3 py-2.5 font-bold rounded-lg text-xs transition-all shadow-sm border cursor-pointer ${
            isDarkMode
              ? 'bg-blue-600 hover:bg-blue-500 border-blue-500 disabled:bg-slate-800 disabled:border-slate-700 disabled:text-slate-600'
              : 'bg-blue-600 hover:bg-blue-700 border-blue-700 shadow-blue-600/20 disabled:bg-slate-200 disabled:border-slate-300 disabled:text-slate-400'
          } text-white disabled:cursor-not-allowed`}
        >
          {isScanning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Collecting Telemetry...</span>
            </>
          ) : (
            <>
              <Server className="w-3.5 h-3.5" />
              <span>Collect Telemetry</span>
            </>
          )}
        </button>

        <button
          onClick={handleRunScan}
          disabled={isScanning || isScanningAll || !selectedDevice}
          className={`w-full flex items-center justify-center gap-2 px-3 py-2.5 font-bold rounded-lg text-xs transition-all shadow-sm border cursor-pointer ${
            isDarkMode
              ? 'bg-emerald-600 hover:bg-emerald-500 border-emerald-500 disabled:bg-slate-800 disabled:border-slate-700 disabled:text-slate-600'
              : 'bg-emerald-600 hover:bg-emerald-700 border-emerald-700 shadow-emerald-600/20 disabled:bg-slate-200 disabled:border-slate-300 disabled:text-slate-400'
          } text-white disabled:cursor-not-allowed`}
        >
          {isScanning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Analyzing...</span>
            </>
          ) : (
            <>
              <Sparkles className="w-3.5 h-3.5" />
              <span>Run AI Assessment</span>
            </>
          )}
        </button>

        <button
          onClick={handleScanAll}
          disabled={isScanning || isScanningAll || devicesLength === 0}
          className={`w-full flex items-center justify-center gap-2 px-3 py-2.5 font-bold rounded-lg text-xs transition-all shadow-sm border cursor-pointer ${
            isDarkMode
              ? 'bg-red-700 hover:bg-red-500 border-red-500 disabled:bg-slate-800 disabled:border-slate-700 disabled:text-slate-600'
              : 'bg-red-700 hover:bg-red-800 border-red-800 shadow-red-600/20 disabled:bg-slate-200 disabled:border-slate-300 disabled:text-slate-400'
          } text-white disabled:cursor-not-allowed`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Scan Inventory ({devicesLength})</span>
        </button>
      </div>
    </aside>
  );
}