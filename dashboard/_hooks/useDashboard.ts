// dashboard/_hooks/useDashboard.ts
import { useState, useEffect, useCallback, useRef } from 'react';
import { toast } from 'sonner';

import { supabase } from '@/lib/supabase';
import { sanitizeConfig } from '@/lib/sanitizer';
import { exportBulkPDF } from '@/lib/bulkExport';

import { NavigationTab, AiCacheEntry, Device, ScanResult } from '../_types/dashboard.types';
import { getHighestRisk } from '../_utils/riskHelpers';
import { api } from '../_utils/api';
import { buildImpactMarkdown } from '../_utils/impactMarkdown';
import { loadDevices, loadLatestScan, latestScanRef, configText } from './dashboardData';
import { watchJob } from './jobWatcher';

export function useDashboard() {
  const [isDarkMode, setIsDarkMode] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<NavigationTab>('inventory');
  const [generatedDate, setGeneratedDate] = useState<string>('');

  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [aiCache, setAiCache] = useState<Record<string, AiCacheEntry>>({});

  const [proposedCommand, setProposedCommand] = useState<string>('');
  const [sandboxAnalysis, setSandboxAnalysis] = useState<string>('');
  const [analyzingCommand, setAnalyzingCommand] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isScanningAll, setIsScanningAll] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<{ current: number; total: number }>({ current: 0, total: 0 });
  const [selectedRiskFilter, setSelectedRiskFilter] = useState<string>('ALL');
  const [isExportingBulk, setIsExportingBulk] = useState<boolean>(false);

  const aiCacheRef = useRef(aiCache);
  aiCacheRef.current = aiCache;
  const stopJobWatch = useRef<(() => void) | null>(null);

  const currentRawConfig = latestScan?.raw_config
    ? sanitizeConfig(latestScan.raw_config)
    : selectedDevice?.last_config
    ? sanitizeConfig(selectedDevice.last_config)
    : '';

  const currentRawVersion =
    latestScan?.raw_version || selectedDevice?.raw_version || (selectedDevice?.os_version ? `Version ${selectedDevice.os_version}` : '');
  const currentOsSummary = latestScan?.os_summary || latestScan?.version_info || '';

  const activeDeviceRisk = selectedDevice?.id ? getHighestRisk(selectedDevice.risk_level, aiCache[selectedDevice.id]?.riskLevel) : 'UNASSESSED';

  const filteredDevices = devices.filter((dev) => {
    if (selectedRiskFilter === 'ALL') return true;
    return (dev.risk_level || 'UNASSESSED').toUpperCase().includes(selectedRiskFilter.toUpperCase());
  });

  const fetchDevices = useCallback(async () => {
    const list = await loadDevices((id) => aiCacheRef.current[id]?.riskLevel);
    setDevices(list);
    setSelectedDevice((prev) => {
      // Deep link from alerts: /?device=<id>
      const wanted = prev?.id || (typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('device') : null);
      return list.find((d) => d.id === wanted) || list[0] || null;
    });
  }, []);

  const fetchScanResults = useCallback(async (deviceId: string) => {
    try {
      setLatestScan(await loadLatestScan(deviceId, aiCacheRef.current[deviceId]?.riskLevel));
    } catch (err) {
      console.error('Error fetching scan results:', err);
    }
  }, []);

  useEffect(() => {
    fetchDevices();
    return () => stopJobWatch.current?.();
  }, [fetchDevices]);

  useEffect(() => {
    if (selectedDevice?.id) fetchScanResults(selectedDevice.id);
  }, [selectedDevice?.id, fetchScanResults]);

  // Live device status (online / unreachable / risk) without polling.
  useEffect(() => {
    const channel = supabase
      .channel('devices-live')
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'devices' }, () => fetchDevices())
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [fetchDevices]);

  async function persistRisk(deviceId: string, riskLevel: string) {
    try {
      await api('/api/update-device-risk', { method: 'POST', json: { deviceId, riskLevel } });
    } catch (err: any) {
      console.error('Failed to persist risk level:', err);
      toast.error(`Database update failed: ${err.message}`);
    }
  }

  async function handleCollectTelemetry() {
    if (!selectedDevice) return;
    const device = selectedDevice;
    setIsScanning(true);
    try {
      const data = await api<{ mode: string; jobId?: string; message: string }>('/api/trigger-collection', { method: 'POST', json: { deviceId: device.id } });

      if (data.mode === 'synthetic') {
        toast.warning('🧪 Demo telemetry generated', { description: data.message });
        await fetchScanResults(device.id);
        await fetchDevices();
        setIsScanning(false);
        return;
      }

      toast.info('📡 Collection queued', { description: 'The AegisApex agent will connect over SSH. This usually takes 10–60 seconds.' });
      stopJobWatch.current?.();
      stopJobWatch.current = watchJob(data.jobId!, async (outcome) => {
        setIsScanning(false);
        if (outcome.status === 'succeeded') {
          toast.success('✅ Telemetry collected', { description: 'Click "Run AI Assessment" to analyze it.' });
        } else if (outcome.status === 'failed') {
          toast.error('❌ Collection failed', { description: outcome.error || 'The agent could not reach the device.' });
        } else {
          toast.error('⏰ Still waiting for the agent', {
            description: 'No agent has picked up the job. Check that agent/worker.py is running and can reach Supabase.',
          });
        }
        await fetchScanResults(device.id);
        await fetchDevices();
      });
    } catch (err: any) {
      toast.error('❌ Collection request failed', { description: err.message });
      setIsScanning(false);
    }
  }

  /** Firmware first (it may create the device's first scans row), then config on that same row. */
  async function assessDevice(device: Device) {
    const before = await latestScanRef(device.id);
    const rawConfig = await configText(device, before?.configuration_id);
    const rawVersion = before?.raw_version || device.raw_version || '';

    const firmware = rawVersion
      ? await api('/api/analyze-firmware', { method: 'POST', json: { deviceId: device.id, rawVersion } }).catch((e) => {
          console.error('Firmware analysis failed:', e);
          return null;
        })
      : null;

    const after = await latestScanRef(device.id);
    const config = rawConfig
      ? await api('/api/scan', {
          method: 'POST',
          json: { deviceId: device.id, scanId: after?.id ?? null, configurationId: after?.configuration_id ?? null, rawConfig, rawVersion },
        }).catch((e) => {
          console.error('Config analysis failed:', e);
          return null;
        })
      : null;

    return { firmware, config, hadConfig: !!rawConfig };
  }

  async function handleRunScan() {
    if (!selectedDevice) return;
    const device = selectedDevice;
    setIsScanning(true);
    try {
      const { firmware, config, hadConfig } = await assessDevice(device);
      if (!hadConfig) {
        toast.warning('⚠️ Missing configuration data', { description: 'Collect telemetry first.' });
        return;
      }
      const findings = config?.findings || [];
      const risk = getHighestRisk(config?.riskLevel, firmware?.riskLevel);

      setAiCache((prev) => ({ ...prev, [device.id]: { config: config?.summary || '', firmware: firmware?.osSummary || '', riskLevel: risk } }));
      await persistRisk(device.id, risk);
      await fetchScanResults(device.id);
      await fetchDevices();

      if (firmware?.kevCount) {
        toast.error(`🚨 ${firmware.kevCount} actively exploited CVE(s) affect this firmware`);
      }
      if (findings.length) toast.error(`🔒 Assessment complete: ${risk}`, { description: `${findings.length} CIS rule(s) violated.` });
      else toast.success('✅ Assessment complete');
    } catch (err: any) {
      toast.error('❌ AI analysis error', { description: err.message });
    } finally {
      setIsScanning(false);
    }
  }

  async function handleScanAll() {
    if (!devices.length || isScanningAll) return;
    setIsScanningAll(true);
    setScanProgress({ current: 0, total: devices.length });
    let failures = 0;
    try {
      // Sequential: each device costs two LLM calls; bursts trigger 429s.
      for (const dev of devices) {
        const { firmware, config } = await assessDevice(dev);
        if (!config && !firmware) failures++;
        const risk = getHighestRisk(config?.riskLevel, firmware?.riskLevel);
        setAiCache((prev) => ({ ...prev, [dev.id]: { config: config?.summary || '', firmware: firmware?.osSummary || '', riskLevel: risk } }));
        if (risk !== 'UNASSESSED') await persistRisk(dev.id, risk);
        setScanProgress((p) => ({ ...p, current: p.current + 1 }));
      }
      await fetchDevices();
      if (selectedDevice?.id) await fetchScanResults(selectedDevice.id);
      toast.success('🚀 Inventory scan finished', {
        description: `${devices.length - failures} of ${devices.length} devices analyzed.${failures ? ' Devices without telemetry were skipped.' : ''}`,
      });
    } catch (error) {
      console.error('Bulk scan error:', error);
      toast.error('❌ Bulk scan failed');
    } finally {
      setIsScanningAll(false);
    }
  }

  async function handleBulkExportPDF() {
    if (!filteredDevices.length || isExportingBulk) {
      toast.warning('⚠️ Export canceled', { description: `No devices matched threat level filter: ${selectedRiskFilter}` });
      return;
    }
    setIsExportingBulk(true);
    try {
      await exportBulkPDF(filteredDevices, selectedRiskFilter);
      toast.success('📄 PDF exported', { description: `Exported ${filteredDevices.length} device reports.` });
    } catch (err: any) {
      toast.error('❌ Export failed', { description: err.message || 'Unknown error generating PDF.' });
    } finally {
      setIsExportingBulk(false);
    }
  }

  async function handleAnalyzeCommand(e: React.FormEvent) {
    e.preventDefault();
    if (!proposedCommand.trim() || !selectedDevice) return;
    setAnalyzingCommand(true);
    setSandboxAnalysis('');
    setActiveTab('sandbox');
    try {
      // The server loads the device's config itself; only the command is sent.
      const data = await api('/api/analyze-impact', {
        method: 'POST',
        json: { deviceId: selectedDevice.id, vendor: selectedDevice.netmiko_type || selectedDevice.vendor, proposedCommand: sanitizeConfig(proposedCommand) },
      });
      setSandboxAnalysis(buildImpactMarkdown(data, selectedDevice.hostname, selectedDevice.vendor));
      toast.info('🧪 Command analysis complete', { description: `Impact: ${data.impactLevel} | Disruption: ${data.disruptionRisk}` });
    } catch (err: any) {
      setSandboxAnalysis(`❌ **Error:** ${err.message}`);
      toast.error('Command analysis error', { description: err.message });
    } finally {
      setAnalyzingCommand(false);
    }
  }

  async function handleAnalyzeFirmware() {
    if (!selectedDevice) return;
    const device = selectedDevice;
    const rawVersion = latestScan?.raw_version || device.raw_version;
    if (!rawVersion) {
      toast.warning('⚠️ Missing "show version" data', { description: 'Collect telemetry first.' });
      return;
    }
    setIsScanning(true);
    try {
      const data = await api('/api/analyze-firmware', { method: 'POST', json: { deviceId: device.id, rawVersion } });
      const unifiedRisk = getHighestRisk(latestScan?.risk_level, data.riskLevel);
      setAiCache((prev) => ({ ...prev, [device.id]: { config: prev[device.id]?.config || '', firmware: data.osSummary, riskLevel: unifiedRisk } }));
      await persistRisk(device.id, unifiedRisk);
      await fetchScanResults(device.id);
      await fetchDevices();
      toast.success('💻 Firmware audit complete', {
        description: `Threat level ${data.riskLevel}; ${data.cves?.length ?? 0} CVE(s)${data.kevCount ? `, ${data.kevCount} actively exploited` : ''}.`,
      });
    } catch (err: any) {
      toast.error('❌ Firmware audit failed', { description: err.message });
    } finally {
      setIsScanning(false);
    }
  }

  const handleExportPDF = (device: Device) => {
    setSelectedDevice(device);
    setGeneratedDate(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }));
    setTimeout(() => window.print(), 150);
  };

  return {
    isDarkMode,
    setIsDarkMode,
    activeTab,
    setActiveTab,
    generatedDate,
    devices,
    selectedDevice,
    setSelectedDevice,
    latestScan,
    aiCache,
    proposedCommand,
    setProposedCommand,
    sandboxAnalysis,
    analyzingCommand,
    isScanning,
    isScanningAll,
    scanProgress,
    selectedRiskFilter,
    setSelectedRiskFilter,
    isExportingBulk,
    filteredDevices,
    currentRawConfig,
    currentRawVersion,
    currentOsSummary,
    activeDeviceRisk,
    fetchDevices,
    handleCollectTelemetry,
    handleRunScan,
    handleScanAll,
    handleBulkExportPDF,
    handleAnalyzeCommand,
    handleAnalyzeFirmware,
    handleExportPDF,
  };
}
