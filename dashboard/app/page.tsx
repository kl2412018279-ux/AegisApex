// dashboard/app/page.tsx
'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { createBrowserClient } from '@supabase/ssr';
import { useDashboard } from '@/_hooks/useDashboard';
import { PrintReport } from '@/_components/PrintReport';
import { FleetPrintReport } from '@/_components/FleetPrintReport';
import { Sidebar } from '@/_components/Sidebar';
import { Header } from '@/_components/Header';
import { InventoryTab } from '@/_components/InventoryTab';
import { ConfigTab } from '@/_components/ConfigTab';
import { VersionTab } from '@/_components/VersionTab';
import { SandboxTab } from '@/_components/SandboxTab';

export default function DashboardPage() {
  const dash = useDashboard();
  const router = useRouter();
  const [printMode, setPrintMode] = useState<'device' | 'fleet' | null>(null);

  // Resolve fresh device from updated devices list to avoid stale state
  const activeDevice =
    dash.devices?.find((d: any) => d.id === dash.selectedDevice?.id) ||
    dash.selectedDevice;

  const handleSignOut = async () => {
    if (typeof (dash as any).handleSignOut === 'function') {
      await (dash as any).handleSignOut();
      return;
    }

    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
    const supabaseKey =
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
      '';

    if (supabaseUrl && supabaseKey) {
      const supabase = createBrowserClient(supabaseUrl, supabaseKey);
      await supabase.auth.signOut();
    }

    router.push('/login');
    router.refresh();
  };

  const handleExportDevicePDF = () => {
    setPrintMode('device');
    // Allow React state to flush & DOM to render before calling native print
    requestAnimationFrame(() => {
      setTimeout(() => {
        window.print();
        setTimeout(() => setPrintMode(null), 300);
      }, 250);
    });
  };

  const handleExportFleetPDF = () => {
    setPrintMode('fleet');
    requestAnimationFrame(() => {
      setTimeout(() => {
        window.print();
        setTimeout(() => setPrintMode(null), 300);
      }, 250);
    });
  };

  return (
    <>
      <style jsx global>{`
        @page {
          size: A4 portrait;
          margin: 10mm;
        }
        @media print {
          *,
          *::before,
          *::after {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }

          html,
          body {
            background: #ffffff !important;
            color: #0f172a !important;
            margin: 0 !important;
            padding: 0 !important;
            width: auto !important;
            height: auto !important;
            overflow: visible !important;
          }

          .print\\:hidden {
            display: none !important;
          }

          .printable-report,
          .printable-fleet-report {
            display: block !important;
            visibility: visible !important;
            position: static !important;
            width: 100% !important;
            height: auto !important;
            margin: 0 !important;
            padding: 0 !important;
            background: #ffffff !important;
            color: #0f172a !important;
          }

          tr,
          .avoid-break {
            page-break-inside: avoid !important;
            break-inside: avoid !important;
          }
        }
      `}</style>

      {/* Printable canvas container — completely hidden on screen, rendered ONLY during browser print */}
      <div className="hidden print:block">
        {printMode === 'device' && (
          <PrintReport
            selectedDevice={activeDevice}
            latestScan={dash.latestScan}
            generatedDate={dash.generatedDate}
            currentOsSummary={dash.currentOsSummary}
            aiCache={dash.aiCache}
          />
        )}

        {printMode === 'fleet' && (
          <FleetPrintReport
            devices={dash.devices || []}
            generatedDate={dash.generatedDate}
          />
        )}
      </div>

      {/* Main Dashboard Application Shell */}
      <div
        className={`print:hidden flex h-screen font-sans overflow-hidden transition-colors duration-200 ${
          dash.isDarkMode ? 'bg-slate-950 text-slate-100' : 'bg-slate-50 text-slate-800'
        }`}
      >
        <Sidebar
          isDarkMode={dash.isDarkMode}
          activeTab={dash.activeTab}
          setActiveTab={dash.setActiveTab}
          selectedDevice={dash.selectedDevice}
          isScanning={dash.isScanning}
          isScanningAll={dash.isScanningAll}
          scanProgress={dash.scanProgress}
          devicesLength={dash.devices?.length || 0}
          handleCollectTelemetry={dash.handleCollectTelemetry}
          handleRunScan={dash.handleRunScan}
          handleScanAll={dash.handleScanAll}
        />

        <main className="flex-1 flex flex-col h-full overflow-hidden">
          <Header
            isDarkMode={dash.isDarkMode}
            setIsDarkMode={dash.setIsDarkMode}
            activeTab={dash.activeTab}
            selectedDevice={dash.selectedDevice}
            setSelectedDevice={dash.setSelectedDevice}
            devices={dash.devices || []}
            activeDeviceRisk={dash.activeDeviceRisk}
            handleExportPDF={handleExportDevicePDF}
            onSignOut={handleSignOut}
          />

          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {dash.activeTab === 'inventory' && (
              <InventoryTab
                isDarkMode={dash.isDarkMode}
                selectedRiskFilter={dash.selectedRiskFilter}
                setSelectedRiskFilter={dash.setSelectedRiskFilter}
                filteredDevices={dash.filteredDevices || []}
                devices={dash.devices || []}
                selectedDevice={dash.selectedDevice}
                setSelectedDevice={dash.setSelectedDevice}
                setActiveTab={dash.setActiveTab}
                aiCache={dash.aiCache}
                isExportingBulk={dash.isExportingBulk}
                handleBulkExportPDF={handleExportFleetPDF}
              />
            )}

            {dash.activeTab === 'config' && (
              <ConfigTab
                isDarkMode={dash.isDarkMode}
                selectedDevice={dash.selectedDevice}
                currentRawConfig={dash.currentRawConfig}
                activeDeviceRisk={dash.activeDeviceRisk}
                aiCache={dash.aiCache}
                latestScan={dash.latestScan}
              />
            )}

            {dash.activeTab === 'version' && (
              <VersionTab
                isDarkMode={dash.isDarkMode}
                selectedDevice={dash.selectedDevice}
                latestScan={dash.latestScan}
                activeDeviceRisk={dash.activeDeviceRisk}
                currentRawVersion={dash.currentRawVersion}
                currentOsSummary={dash.currentOsSummary}
                aiCache={dash.aiCache}
                handleAnalyzeFirmware={dash.handleAnalyzeFirmware}
              />
            )}

            {dash.activeTab === 'sandbox' && (
              <SandboxTab
                isDarkMode={dash.isDarkMode}
                proposedCommand={dash.proposedCommand}
                setProposedCommand={dash.setProposedCommand}
                analyzingCommand={dash.analyzingCommand}
                sandboxAnalysis={dash.sandboxAnalysis}
                handleAnalyzeCommand={dash.handleAnalyzeCommand}
              />
            )}
          </div>
        </main>
      </div>
    </>
  );
}