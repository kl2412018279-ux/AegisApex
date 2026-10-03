// dashboard/app/_hooks/useDashboard.ts
import { useState, useEffect } from 'react';
import { toast } from 'sonner';

import { supabase } from '@/lib/supabase';
import { sanitizeConfig } from '@/lib/sanitizer';
import { exportBulkPDF } from '@/lib/bulkExport';

import { NavigationTab, AiCacheEntry, Device, ScanResult } from '../_types/dashboard.types';
import { getHighestRisk } from '../_utils/riskHelpers';

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
  const [scanProgress, setScanProgress] = useState<{ current: number; total: number }>({
    current: 0,
    total: 0,
  });

  const [selectedRiskFilter, setSelectedRiskFilter] = useState<string>('ALL');
  const [isExportingBulk, setIsExportingBulk] = useState<boolean>(false);

  // Derived state getters
  const currentRawConfig = latestScan?.raw_config
    ? sanitizeConfig(latestScan.raw_config)
    : selectedDevice?.last_config
    ? sanitizeConfig(selectedDevice.last_config)
    : '';

  const currentRawVersion =
    latestScan?.raw_version ||
    latestScan?.show_version ||
    latestScan?.os_version ||
    selectedDevice?.raw_version ||
    ((selectedDevice as any)?.os_version ? `Cisco IOS Software, Version ${(selectedDevice as any).os_version}` : '');

  const currentOsSummary = latestScan?.os_summary || latestScan?.version_info || '';

  const activeDeviceRisk = selectedDevice?.id
    ? getHighestRisk(selectedDevice.risk_level, aiCache[selectedDevice.id]?.riskLevel)
    : 'UNASSESSED';

  const filteredDevices = devices.filter((dev) => {
    if (selectedRiskFilter === 'ALL') return true;
    const risk = (dev.risk_level || 'UNASSESSED').toUpperCase();
    return risk.includes(selectedRiskFilter.toUpperCase());
  });

  useEffect(() => {
    fetchDevices();
  }, []);

  useEffect(() => {
    if (selectedDevice?.id) {
      fetchScanResults(selectedDevice.id);
    }
  }, [selectedDevice?.id]);

  async function fetchDevices() {
    const { data: devicesData, error: devError } = await supabase
      .from('devices')
      .select('*, suppliers(*)');

    if (devError || !devicesData || devicesData.length === 0) {
      if (devError) console.error('Supabase devices fetch error:', devError);
      setDevices([]);
      return;
    }

    const { data: scansData, error: scanError } = await supabase
      .from('scans')
      .select('device_id, risk_level, created_at')
      .order('created_at', { ascending: false });

    if (scanError) console.warn('Could not fetch scans metadata:', scanError);

    const scanMap: Record<string, string> = {};
    if (scansData) {
      for (const scan of scansData) {
        if (scan.device_id && !scanMap[scan.device_id] && scan.risk_level) {
          scanMap[scan.device_id] = scan.risk_level;
        }
      }
    }

    const formattedDevices: Device[] = devicesData.map((d: any) => {
      const dbScanRisk = scanMap[d.id];
      const cachedRisk = aiCache[d.id]?.riskLevel;

      const highestDbRisk = getHighestRisk(d.risk_level, dbScanRisk);
      const normalizedRisk = getHighestRisk(highestDbRisk, cachedRisk);

      return {
        id: d.id,
        hostname: d.hostname || 'Unknown Host',
        ip_address: d.ip_address || d.management_ip || d.ip || '127.0.0.1',
        vendor: d.vendor || d.device_type || 'cisco',
        netmiko_type: d.netmiko_type || d.device_type || 'cisco_ios',
        suppliers: d.suppliers || null,
        connection_status: d.connection_status || 'online',
        last_seen_at: d.last_seen_at || d.created_at,
        risk_level: normalizedRisk,
        ssh_user: d.ssh_user || null,
        ssh_pass: d.ssh_pass || null,
        last_config: d.last_config || null,
        raw_version: d.raw_version || d.os_version || null,
        os_version: d.os_version || null,
      };
    });

    setDevices(formattedDevices);
    setSelectedDevice((prev: any) => {
      if (!prev) return formattedDevices[0];
      const updated = formattedDevices.find((fd: any) => fd.id === prev.id);
      return updated || formattedDevices[0];
    });
  }

  async function fetchScanResults(deviceId: string) {
    if (!deviceId) return;

    try {
      const { data: scanData, error: scanErr } = await supabase
        .from('scans')
        .select('*')
        .eq('device_id', deviceId)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (!scanData || scanErr) {
        setLatestScan(null);
        return;
      }

      let rawConfigText = '';
      if (scanData.configuration_id) {
        const { data: configData } = await supabase
          .from('configurations')
          .select('*')
          .eq('id', scanData.configuration_id)
          .maybeSingle();
        rawConfigText = configData?.raw_config || configData?.content || '';
      }

      let vulns: any[] = [];
      if (scanData.id) {
        const { data: vulnData } = await supabase
          .from('vulnerabilities')
          .select('*')
          .eq('scan_id', scanData.id);
        vulns = vulnData || [];
      }

      if (vulns.length === 0) {
        const jsonFindings = scanData.vulnerabilities || scanData.findings;
        if (Array.isArray(jsonFindings)) {
          vulns = jsonFindings;
        } else if (typeof jsonFindings === 'string') {
          try {
            vulns = JSON.parse(jsonFindings);
          } catch (e) {
            console.error('Error parsing JSON findings:', e);
          }
        }
      }

      let osSummaryText = scanData.os_summary || '';
      let versionInfoText = scanData.os_summary || scanData.summary || '';

      if (!osSummaryText && scanData.summary && !scanData.summary.includes('Telemetry collected')) {
        osSummaryText = scanData.summary;
        versionInfoText = scanData.summary;
      }

      if (osSummaryText && !osSummaryText.includes('OS/Firmware Security Analysis') && !osSummaryText.includes('🔍')) {
        if (osSummaryText.length < 100 && !osSummaryText.includes('\n')) {
          osSummaryText =
            `🔍 **OS/Firmware Security Analysis**\n\n` +
            `**Version Detected:** ${osSummaryText}\n\n` +
            `*Run "Re-analyze Firmware" for detailed security assessment.*`;
        } else {
          osSummaryText = `🔍 **OS/Firmware Security Analysis**\n\n${osSummaryText}`;
          versionInfoText = osSummaryText;
        }
      }

      if (!osSummaryText && scanData.raw_version) {
        const rawPreview = scanData.raw_version.substring(0, 300);
        osSummaryText =
          `📡 **Raw Version Data Collected**\n\n` +
          `\`\`\`\n${rawPreview}${scanData.raw_version.length > 300 ? '...' : ''}\n\`\`\`\n\n` +
          `Click "Run AI Assessment" or "Re-analyze Firmware" to generate detailed security analysis.`;
        versionInfoText = osSummaryText;
      }

      if (vulns && vulns.length > 0) {
        let findingsSection = '\n\n**🔒 Security Findings:**\n\n';
        vulns.slice(0, 5).forEach((v: any) => {
          const severity = v.severity || v.risk_level || 'Medium';
          const emoji = severity === 'Critical' ? '🔴' : severity === 'High' ? '🟠' : severity === 'Medium' ? '🟡' : '🟢';
          const title = v.title || v.name || v.id || 'Security Issue';
          const desc = v.description || v.summary || v.remediation || '';
          findingsSection += `${emoji} **${title}**\n   ${desc}\n\n`;
        });
        if (vulns.length > 5) {
          findingsSection += `*... and ${vulns.length - 5} more findings*`;
        }

        if (!osSummaryText.includes('Security Findings')) {
          osSummaryText += findingsSection;
        }
      }

      let displaySummary = scanData.summary;
      if ((!displaySummary || displaySummary.includes('Telemetry collected')) && vulns.length > 0) {
        displaySummary = `Security Audit completed: ${vulns.length} risk finding(s) detected.`;
      }

      const calculatedScanRisk = scanData.risk_level || (vulns.length > 0 ? 'HIGH' : 'LOW');
      const cachedRisk = aiCache[deviceId]?.riskLevel;
      const normalizedThreatLevel = getHighestRisk(calculatedScanRisk, cachedRisk);

      setLatestScan({
        scanned_at: scanData.created_at || new Date().toISOString(),
        raw_config: rawConfigText ? sanitizeConfig(rawConfigText) : '',
        risk_level: normalizedThreatLevel,
        summary: displaySummary || 'No summary available',
        vulnerabilities: vulns,
        model_used: scanData.model_used || 'Groq Llama-3',
        raw_version: scanData.raw_version || '',
        show_version: scanData.raw_version || '',
        os_version: scanData.raw_version || '',
        os_summary: osSummaryText,
        version_info: versionInfoText,
        os_cves: [],
        target_firmware: scanData.target_firmware || 'Not yet analyzed',
        eol_status: scanData.eol_status || 'Not yet analyzed',
      });
    } catch (err) {
      console.error('Error fetching scan results:', err);
    }
  }

  async function handleCollectTelemetry() {
    if (!selectedDevice) return;
    setIsScanning(true);
    const triggerStartTime = new Date().toISOString(); // Timestamp marker to prevent false polling success

    try {
      const res = await fetch('/api/trigger-collection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceId: selectedDevice.id }),
      });

      const data = await res.json();

      if (res.ok) {
        toast.info('📡 Telemetry Collection Started', {
          description: 'SSH agent fetching show running-config and show version. This may take 10-30s.',
        });

        let attempts = 0;
        const maxAttempts = 30;
        const pollInterval = setInterval(async () => {
          attempts++;
          // Filter by created_at > triggerStartTime to only detect NEW scans generated by the collector
          const { data: scanData } = await supabase
            .from('scans')
            .select('*')
            .eq('device_id', selectedDevice.id)
            .gt('created_at', triggerStartTime)
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

          if (scanData) {
            clearInterval(pollInterval);
            setIsScanning(false);
            toast.success('✅ Telemetry Collection Complete!', {
              description: 'Click "Run AI Assessment" to analyze the updated telemetry data.',
            });
            await fetchScanResults(selectedDevice.id);
            await fetchDevices();
          } else if (attempts >= maxAttempts) {
            clearInterval(pollInterval);
            setIsScanning(false);
            toast.error('⏰ Telemetry Collection Timed Out', {
              description: 'Please check if the SSH agent is running and reachability to the device.',
            });
          }
        }, 2000);
      } else {
        toast.error('❌ Collection Failed', {
          description: data.error || 'Unknown server error occurred.',
        });
        setIsScanning(false);
      }
    } catch (err: any) {
      console.error('Error triggering collection:', err);
      toast.error('❌ Network Error', {
        description: err.message,
      });
      setIsScanning(false);
    }
  }

  async function handleRunScan() {
    if (!selectedDevice) return;
    setIsScanning(true);

    try {
      const { data: existingScans } = await supabase
        .from('scans')
        .select('*')
        .eq('device_id', selectedDevice.id)
        .order('created_at', { ascending: false })
        .limit(1);

      const scan = existingScans && existingScans.length > 0 ? existingScans[0] : null;

      let rawConfigContent = selectedDevice.last_config || '';
      if (!rawConfigContent && scan?.configuration_id) {
        const { data: configData } = await supabase
          .from('configurations')
          .select('*')
          .eq('id', scan.configuration_id)
          .maybeSingle();
        rawConfigContent = configData?.raw_config || configData?.content || '';
      }

      if (!rawConfigContent) {
        toast.warning('⚠️ Missing Configuration Data', {
          description: 'No telemetry configuration found for this device. Please collect telemetry first.',
        });
        setIsScanning(false);
        return;
      }

      const rawVersionContent = scan?.raw_version || selectedDevice.raw_version || (selectedDevice as any).os_version || '';

      let osAnalysisResult: any = null;
      let configAnalysisResult: any = null;

      if (rawVersionContent) {
        try {
          const firmwareRes = await fetch('/api/analyze-firmware', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: selectedDevice.id,
              vendor: selectedDevice.vendor || 'Cisco',
              rawVersion: rawVersionContent,
            }),
          });

          if (firmwareRes.ok) osAnalysisResult = await firmwareRes.json();
        } catch (err) {
          console.error('Error in OS analysis:', err);
        }
      }

      try {
        const configRes = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deviceId: selectedDevice.id,
            // FIX: this call never passed scanId, so /api/scan's own
            // persistence logic always took its INSERT branch — forking a
            // brand-new `scans` row instead of updating the one the
            // /api/analyze-firmware call directly above just wrote
            // target_firmware/eol_status into. That new row became the
            // "latest" scan by created_at with those two fields empty, so
            // the very next fetchScanResults() picked up the fresh, blank
            // row and showed "Not yet analyzed" even though the real AI
            // answer had been persisted to the database seconds earlier, to
            // a different, now-orphaned row. Passing scan?.id here makes
            // /api/scan update that same row instead of forking a duplicate,
            // so "Run AI Assessment" and "Re-analyze Firmware" now leave the
            // device in the same state instead of disagreeing.
            scanId: scan?.id || null,
            configurationId: scan?.configuration_id || null,
            vendor: selectedDevice.vendor || 'Cisco',
            rawConfig: rawConfigContent,
            rawVersion: rawVersionContent,
          }),
        });

        if (configRes.ok) configAnalysisResult = await configRes.json();
      } catch (err) {
        console.error('Error in config analysis:', err);
      }

      const finalVulns = configAnalysisResult?.vulnerabilities || configAnalysisResult?.findings || [];
      const configRisk = configAnalysisResult?.riskLevel || (finalVulns.length > 0 ? 'HIGH' : 'LOW');
      const osRisk = osAnalysisResult?.riskLevel || 'LOW';
      const normalizedUnifiedRisk = getHighestRisk(configRisk, osRisk);

      const finalSummary = configAnalysisResult?.summary || 'AI Security Assessment completed successfully.';
      const finalOsSummary = osAnalysisResult?.osSummary || scan?.os_summary || '';

      setAiCache((prev) => ({
        ...prev,
        [selectedDevice.id]: {
          config: finalSummary,
          firmware: finalOsSummary,
          riskLevel: normalizedUnifiedRisk,
        },
      }));

      try {
        const res = await fetch('/api/update-device-risk', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deviceId: selectedDevice.id,
            riskLevel: normalizedUnifiedRisk,
          }),
        });

        const resData = await res.json().catch(() => ({}));
        if (!res.ok) {
          console.error('DB Update error:', resData.error);
          toast.error(`Database Update Failed: ${resData.error || 'Unknown error'}`);
        }
      } catch (err: any) {
        console.error('Failed to update single device risk level:', err);
        toast.error(`Network Error Updating Database: ${err.message}`);
      }

      await fetchScanResults(selectedDevice.id);
      await fetchDevices();

      if (finalVulns.length > 0) {
        toast.error(`🔒 AI Scan Complete: ${normalizedUnifiedRisk} Risk`, {
          description: `Detected ${finalVulns.length} potential security vulnerability(ies).`,
        });
      } else {
        toast.success('✅ AI Analysis Complete');
      }
    } catch (err: any) {
      console.error('Error in AI analysis:', err);
      toast.error('❌ AI Analysis Error', {
        description: err.message,
      });
    } finally {
      setIsScanning(false);
    }
  }

  async function handleScanAll() {
    if (!devices || devices.length === 0 || isScanningAll) return;

    setIsScanningAll(true);
    setScanProgress({ current: 0, total: devices.length });

    try {
      const scanPromises = devices.map(async (dev) => {
        const { data: scanData } = await supabase
          .from('scans')
          .select('*')
          .eq('device_id', dev.id)
          .order('created_at', { ascending: false })
          .limit(1);

        const latestScanRecord = scanData && scanData.length > 0 ? scanData[0] : null;

        let configContent = dev.last_config || '';
        if (!configContent && latestScanRecord?.configuration_id) {
          const { data: cfg } = await supabase
            .from('configurations')
            .select('raw_config, content')
            .eq('id', latestScanRecord.configuration_id)
            .maybeSingle();
          configContent = cfg?.raw_config || cfg?.content || '';
        }

        const versionContent = dev.raw_version || (dev as any).os_version || latestScanRecord?.raw_version || '';

        const [configRes, firmwareRes] = await Promise.all([
          fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: dev.id,
              // FIX: same gap as handleRunScan above — this bulk path never
              // passed scanId either, so every "Scan All Inventory" run
              // forked a brand-new scans row per device instead of updating
              // the existing one, stranding any target_firmware/eol_status
              // the paired /api/analyze-firmware call (below) had just
              // written to the old row.
              scanId: latestScanRecord?.id || null,
              vendor: dev.vendor || 'Cisco',
              rawConfig: configContent,
              rawVersion: versionContent,
              configurationId: latestScanRecord?.configuration_id || null,
            }),
          }).then((r) => (r.ok ? r.json() : null)).catch(() => null),

          fetch('/api/analyze-firmware', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: dev.id,
              vendor: dev.vendor || 'Cisco',
              rawVersion: versionContent,
            }),
          }).then((r) => (r.ok ? r.json() : null)).catch(() => null),
        ]);

        const configText = configRes?.output || configRes?.summary || '';
        const firmwareText = firmwareRes?.output || firmwareRes?.osSummary || firmwareRes?.summary || '';
        const computedDevRisk = getHighestRisk(configRes?.riskLevel, firmwareRes?.riskLevel);

        setScanProgress((prev) => ({ ...prev, current: prev.current + 1 }));

        return {
          id: dev.id,
          hostname: dev.hostname,
          ip: dev.ip_address,
          configText,
          firmwareText,
          riskLevel: computedDevRisk,
        };
      });

      const results = await Promise.all(scanPromises);

      const newCache: Record<string, AiCacheEntry> = {};

      results.forEach((res) => {
        newCache[res.id] = {
          config: res.configText,
          firmware: res.firmwareText,
          riskLevel: res.riskLevel,
        };
      });

      setAiCache((prev) => ({ ...prev, ...newCache }));

      await Promise.all(
        results.map(async (res) => {
          if (!res.riskLevel) return;
          try {
            const apiRes = await fetch('/api/update-device-risk', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                deviceId: res.id,
                riskLevel: res.riskLevel,
              }),
            });

            const apiData = await apiRes.json().catch(() => ({}));
            if (!apiRes.ok) {
              console.error(`DB Update error for device ${res.id}:`, apiData.error);
            }
          } catch (err) {
            console.error(`Failed to update risk level for device ${res.id}:`, err);
          }
        })
      );

      await fetchDevices();

      toast.success('🚀 Bulk Inventory Scan Finished', {
        description: `Successfully analyzed ${results.length} devices. Saved to database.`,
      });

      if (selectedDevice?.id) {
        await fetchScanResults(selectedDevice.id);
      }
    } catch (error) {
      console.error('Error during bulk scan:', error);
      toast.error('❌ Bulk Scan Failed', {
        description: 'An unexpected error occurred while auditing inventory.',
      });
    } finally {
      setIsScanningAll(false);
    }
  }

  async function handleBulkExportPDF() {
    if (filteredDevices.length === 0 || isExportingBulk) {
      toast.warning('⚠️ Export Canceled', {
        description: `No devices matched threat level filter: ${selectedRiskFilter}`,
      });
      return;
    }

    setIsExportingBulk(true);

    try {
      await exportBulkPDF(filteredDevices, selectedRiskFilter);
      toast.success('📄 PDF Exported', {
        description: `Exported ${filteredDevices.length} device reports.`,
      });
    } catch (err: any) {
      console.error('Failed to export bulk PDF:', err);
      toast.error('❌ Export Failed', {
        description: err.message || 'Unknown error generating PDF.',
      });
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

    const sanitizedCommand = sanitizeConfig(proposedCommand);

    try {
      const res = await fetch('/api/analyze-impact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vendor: selectedDevice.vendor,
          activeConfig: currentRawConfig || latestScan?.raw_config || '',
          proposedCommand: sanitizedCommand,
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        const impactLevel = (data.impactLevel || data.suggestedAction?.riskLevel || 'Unknown').toUpperCase();
        const disruptionRisk = (data.disruptionRisk || (data.suggestedAction?.requiresHumanApproval ? 'High' : 'Moderate')).toUpperCase();
        const summary = data.analysis || data.impactSummary || '';
        const rationale = data.suggestedAction?.rationale || '';
        const suggestedCmd = data.suggestedAction?.command || '';
        const vendorLang = (selectedDevice.vendor || 'cisco').toLowerCase();

        let rollbacks: string[] = [];
        if (Array.isArray(data.rollbackCommands)) {
          rollbacks = data.rollbackCommands
            .flatMap((cmd: any) => String(cmd).replace(/\\n/g, '\n').split(/\r?\n/))
            .map((cmd: string) => cmd.trim())
            .filter(Boolean);
        } else if (typeof data.rollbackCommands === 'string') {
          rollbacks = data.rollbackCommands
            .replace(/\\n/g, '\n')
            .split(/\r?\n/)
            .map((cmd: string) => cmd.trim())
            .filter(Boolean);
        }

        let analysisText = `## 📊 CLI Command Impact Assessment\n\n`;
        analysisText += `> **Target Device:** \`${selectedDevice.hostname || 'Device'}\` (${selectedDevice.vendor?.toUpperCase() || 'GENERIC'})\n\n`;
        analysisText += `### 🎯 Assessment Metrics\n`;
        analysisText += `* **Impact Level:** **${impactLevel}**\n`;
        analysisText += `* **Disruption Risk:** **${disruptionRisk}**\n\n`;

        if (summary) {
          analysisText += `### 🔍 Analysis & Disruption Breakdown\n${summary}\n\n`;
        }

        if (rationale) {
          analysisText += `### 💡 Operational Rationale\n${rationale}\n\n`;
        }

        if (suggestedCmd) {
          const cleanSuggested = String(suggestedCmd).replace(/\\n/g, '\n').trim();
          analysisText += `### 🛠️ Suggested Execution Command\n\`\`\`${vendorLang}\n${cleanSuggested}\n\`\`\`\n\n`;
        }

        if (rollbacks.length > 0) {
          analysisText += `### 🔄 Disaster Recovery Rollback Script\n`;
          analysisText += `*Execute these commands to revert changes if service is disrupted:*\n\n`;
          analysisText += `\`\`\`${vendorLang}\n${rollbacks.join('\n')}\n\`\`\`\n`;
        }

        setSandboxAnalysis(analysisText);
        toast.info('🧪 Command Analysis Complete', {
          description: `Impact: ${impactLevel} | Disruption: ${disruptionRisk}`,
        });
      } else {
        setSandboxAnalysis(`❌ **Error (${res.status}):** ${data.error || 'Failed to process command'}`);
        toast.error('Command analysis error', { description: data.error });
      }
    } catch (err: any) {
      setSandboxAnalysis(`❌ **System Error:** ${err.message}`);
      toast.error('System error analyzing command', { description: err.message });
    } finally {
      setAnalyzingCommand(false);
    }
  }

  async function handleAnalyzeFirmware() {
    if (!selectedDevice) return;

    const rawVer =
      latestScan?.raw_version ||
      latestScan?.show_version ||
      latestScan?.os_version ||
      selectedDevice?.raw_version ||
      (selectedDevice as any)?.os_version ||
      selectedDevice?.last_config;

    if (!rawVer) {
      toast.warning('⚠️ Missing Raw Version', {
        description: 'Missing raw version data for this device. Collect telemetry first.',
      });
      return;
    }

    setIsScanning(true);
    try {
      const res = await fetch('/api/analyze-firmware', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceId: selectedDevice.id,
          vendor: selectedDevice.vendor,
          rawVersion: rawVer,
        }),
      });

      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        if (data?.osSummary || data?.os_summary || data?.analysis) {
          const newOsSummary = data.osSummary || data.os_summary || data.analysis;
          const fwRisk = data.riskLevel || 'LOW';
          const unifiedRisk = getHighestRisk(latestScan?.risk_level, fwRisk);

          const targetFw = data.targetFirmware || data.recommendedVersion || data.target_firmware || 'Recommended Baseline Standard';
          const eolState = data.eolStatus || data.lifecycleStatus || data.eol_status || 'Mainstream Active';

          setLatestScan((prev) =>
            prev
              ? {
                  ...prev,
                  risk_level: unifiedRisk,
                  os_summary: newOsSummary,
                  version_info: newOsSummary,
                  target_firmware: targetFw,
                  eol_status: eolState,
                }
              : null
          );

          setAiCache((prev) => ({
            ...prev,
            [selectedDevice.id]: {
              config: prev[selectedDevice.id]?.config || '',
              firmware: newOsSummary,
              riskLevel: unifiedRisk,
            },
          }));

          try {
            await fetch('/api/update-device-risk', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                deviceId: selectedDevice.id,
                riskLevel: unifiedRisk,
              }),
            });
          } catch (err) {
            console.error('Failed to persist firmware risk level:', err);
          }

          await fetchDevices();

          toast.success('💻 Firmware Audit Complete', {
            description: `OS firmware analysis updated (Threat Level: ${fwRisk}).`,
          });
        }
      } else {
        const errData = await res.json().catch(() => ({}));
        toast.error('❌ Firmware Audit Failed', {
          description: errData.error || 'Unknown server error during firmware assessment.',
        });
      }
    } catch (err: any) {
      console.error('Failed to trigger firmware audit:', err);
      toast.error('❌ Error Running Firmware Audit', {
        description: err.message,
      });
    } finally {
      // FIX: always release the lock, success or failure, so the button
      // isn't stuck disabled forever if the request errors out.
      setIsScanning(false);
    }
  }

  const handleExportPDF = (device: Device) => {
    setSelectedDevice(device);
    setGeneratedDate(
      new Date().toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    );
    setTimeout(() => {
      window.print();
    }, 150);
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
    handleCollectTelemetry,
    handleRunScan,
    handleScanAll,
    handleBulkExportPDF,
    handleAnalyzeCommand,
    handleAnalyzeFirmware,
    handleExportPDF,
  };
}