//header.tsx
import React, { useState, useRef, useEffect } from 'react';
import {
  Server,
  FileText,
  Cpu,
  Terminal as TerminalIcon,
  Sun,
  Moon,
  Download,
  ChevronDown,
  Check,
  LogOut,
} from 'lucide-react';
import { NavigationTab, Device } from '../_types/dashboard.types';

interface HeaderProps {
  isDarkMode: boolean;
  setIsDarkMode: (val: boolean) => void;
  activeTab: NavigationTab;
  selectedDevice: Device | null;
  setSelectedDevice: (dev: Device) => void;
  devices: Device[];
  activeDeviceRisk: string;
  handleExportPDF: (dev: Device) => void;
  onSignOut?: () => void;
}

const TAB_CONFIG: Record<
  string,
  { icon: React.ElementType; title: string; darkClass: string; lightClass: string }
> = {
  inventory: {
    icon: Server,
    title: 'Infrastructure Device Inventory',
    darkClass: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
    lightClass: 'bg-emerald-50/80 border-emerald-200 text-emerald-700',
  },
  config: {
    icon: FileText,
    title: 'Running Configuration & Security Audit',
    darkClass: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
    lightClass: 'bg-purple-50/80 border-purple-200 text-purple-700',
  },
  version: {
    icon: Cpu,
    title: 'OS Firmware Version & Lifecycle Assessment',
    darkClass: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
    lightClass: 'bg-blue-50/80 border-blue-200 text-blue-700',
  },
  sandbox: {
    icon: TerminalIcon,
    title: 'CLI Command Impact Simulation Sandbox',
    darkClass: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
    lightClass: 'bg-amber-50/80 border-amber-200 text-amber-700',
  },
};

const getBadgeStyle = (risk: string, isDarkMode: boolean) => {
  const norm = (risk || '').toUpperCase();
  switch (norm) {
    case 'CRITICAL':
      return isDarkMode
        ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
        : 'bg-rose-100 text-rose-800 border-rose-200';
    case 'HIGH':
      return isDarkMode
        ? 'bg-orange-500/20 text-orange-300 border-orange-500/30'
        : 'bg-orange-100 text-orange-800 border-orange-200';
    case 'MEDIUM':
    case 'WARNING':
      return isDarkMode
        ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
        : 'bg-amber-100 text-amber-800 border-amber-200';
    case 'LOW':
    case 'SECURE':
    case 'CLEAN':
    case 'SAFE':
      return isDarkMode
        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
        : 'bg-emerald-100 text-emerald-800 border-emerald-200';
    default:
      return isDarkMode
        ? 'bg-slate-800 text-slate-300 border-slate-700'
        : 'bg-slate-100 text-slate-700 border-slate-200';
  }
};

export function Header({
  isDarkMode,
  setIsDarkMode,
  activeTab,
  selectedDevice,
  setSelectedDevice,
  devices,
  activeDeviceRisk,
  handleExportPDF,
  onSignOut,
}: HeaderProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const cardBtnStyle = isDarkMode
    ? 'bg-slate-800/80 hover:bg-slate-800 border-slate-700/70 text-slate-200 shadow-sm'
    : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-800 shadow-xs';

  const currentTab = TAB_CONFIG[activeTab] || TAB_CONFIG.inventory;
  const TabIcon = currentTab.icon;

  return (
    <header
      className={`h-16 border-b px-6 flex items-center justify-between shrink-0 transition-colors duration-200 ${
        isDarkMode
          ? 'bg-slate-900 border-slate-800 text-slate-100'
          : 'bg-white border-slate-200 text-slate-900'
      }`}
    >
      {/* Tab Heading */}
      <div className="flex items-center gap-3">
        <div
          className={`p-2 rounded-lg border transition-colors ${
            isDarkMode ? currentTab.darkClass : currentTab.lightClass
          }`}
        >
          <TabIcon className="w-4.5 h-4.5" />
        </div>
        <h2 className="text-base font-bold tracking-tight">{currentTab.title}</h2>
      </div>

      {/* Control Actions */}
      <div className="flex items-center gap-2.5">
        {/* Device Selection Dropdown */}
        <div className="relative" ref={dropdownRef}>
          <button
            type="button"
            onClick={() => setIsOpen(!isOpen)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-all text-xs cursor-pointer ${cardBtnStyle}`}
          >
            <span className="font-mono uppercase text-[10px] font-bold text-slate-500 hidden md:inline">
              Target:
            </span>

            {selectedDevice ? (
              <div className="flex items-center gap-2">
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border uppercase tracking-wider ${getBadgeStyle(
                    activeDeviceRisk,
                    isDarkMode
                  )}`}
                >
                  {activeDeviceRisk}
                </span>
                <span className="font-mono font-semibold truncate max-w-[140px] sm:max-w-[200px]">
                  {selectedDevice.hostname} ({selectedDevice.ip_address || (selectedDevice as any).management_ip || 'No IP'})
                </span>
              </div>
            ) : (
              <span className="font-mono text-slate-400">Select Target Device...</span>
            )}

            <ChevronDown
              className={`w-3.5 h-3.5 text-slate-400 transition-transform ${
                isOpen ? 'rotate-180' : ''
              }`}
            />
          </button>

          {/* Dropdown Popover */}
          {isOpen && (
            <div
              className={`absolute right-0 mt-2 w-80 rounded-xl border shadow-lg z-50 overflow-hidden py-1 ${
                isDarkMode
                  ? 'bg-slate-900 border-slate-800 text-slate-100'
                  : 'bg-white border-slate-200 text-slate-900'
              }`}
            >
              <div className="max-h-64 overflow-y-auto">
                {devices.map((d) => {
                  const displayIp = d.ip_address || (d as any).management_ip || 'No IP';
                  const threatState = (d.risk_level || 'UNASSESSED').toUpperCase();
                  const isSelected = selectedDevice?.id === d.id;

                  return (
                    <button
                      key={d.id}
                      type="button"
                      onClick={() => {
                        setSelectedDevice(d);
                        setIsOpen(false);
                      }}
                      className={`w-full text-left px-3 py-2 text-xs font-mono flex items-center justify-between transition-colors cursor-pointer ${
                        isSelected
                          ? isDarkMode
                            ? 'bg-slate-800 text-white font-bold'
                            : 'bg-slate-100 text-slate-900 font-bold'
                          : isDarkMode
                          ? 'hover:bg-slate-800/60 text-slate-300'
                          : 'hover:bg-slate-50 text-slate-700'
                      }`}
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border uppercase tracking-wider shrink-0 ${getBadgeStyle(
                            threatState,
                            isDarkMode
                          )}`}
                        >
                          {threatState}
                        </span>
                        <span className="truncate">
                          {d.hostname}{' '}
                          <span className="text-slate-400">({displayIp})</span>
                        </span>
                      </div>
                      {isSelected && <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0 ml-2" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Theme Toggle */}
        <button
          onClick={() => setIsDarkMode(!isDarkMode)}
          className={`p-2 rounded-lg border transition-all cursor-pointer ${cardBtnStyle}`}
          title="Toggle Theme"
          aria-label="Toggle Theme"
        >
          {isDarkMode ? (
            <Sun className="w-4 h-4 text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 text-slate-600" />
          )}
        </button>

        {/* Export PDF Report */}
        {selectedDevice && (
          <button
            onClick={() => handleExportPDF(selectedDevice)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${cardBtnStyle}`}
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden md:inline">Export PDF</span>
          </button>
        )}

        {/* Sign Out Button */}
        <button
          onClick={onSignOut}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
            isDarkMode
              ? 'bg-rose-500/10 border-rose-500/20 text-rose-400 hover:bg-rose-500/20'
              : 'bg-rose-50 border-rose-200 text-rose-700 hover:bg-rose-100'
          }`}
          title="Sign Out"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Sign Out</span>
        </button>
      </div>
    </header>
  );
}