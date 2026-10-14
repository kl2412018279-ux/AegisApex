// dashboard/_hooks/dashboardData.ts
// Data loading for the dashboard. The inventory comes from /api/devices;
// the rest are browser reads scoped by Row Level Security.
import { supabase } from '@/lib/supabase';
import { sanitizeConfig } from '@/lib/sanitizer';
import type { Device, ScanResult, Vulnerability } from '../_types/dashboard.types';
import { getHighestRisk } from '../_utils/riskHelpers';
import { api } from '../_utils/api';

export async function loadDevices(cachedRisk: (id: string) => string | undefined): Promise<Device[]> {
  let data: any[];
  try {
    // Server-side read: works with any devices schema and never exposes
    // credential columns (see app/api/devices/route.ts).
    ({ devices: data } = await api<{ devices: any[] }>('/api/devices'));
  } catch (error) {
    console.error('Device inventory fetch error:', error);
    throw error;
  }

  const { data: scans } = await supabase.from('scans').select('device_id, risk_level, created_at').order('created_at', { ascending: false });
  const latestScanRisk: Record<string, string> = {};
  for (const s of scans || []) {
    if (s.device_id && s.risk_level && !latestScanRisk[s.device_id]) latestScanRisk[s.device_id] = s.risk_level;
  }

  return data.map((d) => ({
    ...d,
    hostname: d.hostname || 'Unknown Host',
    ip_address: d.ip_address || d.management_ip || d.ip || '',
    vendor: d.vendor || d.device_type || 'cisco',
    netmiko_type: d.netmiko_type || d.device_type || 'cisco_ios',
    suppliers: d.suppliers || null,
    connection_status: d.connection_status || 'unknown',
    last_seen_at: d.last_seen_at || d.created_at,
    risk_level: getHighestRisk(d.risk_level, latestScanRisk[d.id], cachedRisk(d.id)),
    raw_version: d.raw_version || d.os_version || null,
  }));
}

function osSummaryFor(scan: any): { os: string; versionInfo: string } {
  // Only /api/analyze-firmware writes os_summary; never fall back to the
  // config audit text in scans.summary.
  let os = scan.os_summary || '';
  let versionInfo = os;
  if (os && !os.includes('OS/Firmware Security') && !os.includes('🔍')) {
    if (os.length < 100 && !os.includes('\n')) {
      os = `🔍 **OS/Firmware Security Analysis**\n\n**Version Detected:** ${os}\n\n*Run "Re-analyze Firmware" for a detailed assessment.*`;
    } else {
      os = `🔍 **OS/Firmware Security Analysis**\n\n${os}`;
      versionInfo = os;
    }
  }
  return { os, versionInfo };
}

export async function loadLatestScan(deviceId: string, cachedRisk?: string): Promise<ScanResult | null> {
  const { data: scan } = await supabase.from('scans').select('*').eq('device_id', deviceId).order('created_at', { ascending: false }).limit(1).maybeSingle();
  if (!scan) return null;

  let rawConfig = '';
  if (scan.configuration_id) {
    const { data: cfg } = await supabase.from('configurations').select('raw_config, content').eq('id', scan.configuration_id).maybeSingle();
    rawConfig = cfg?.raw_config || cfg?.content || '';
  }
  const { data: vulnRows } = await supabase.from('vulnerabilities').select('*').eq('scan_id', scan.id);
  const vulns: Vulnerability[] = vulnRows || [];

  let summary = scan.summary;
  if ((!summary || summary.includes('Telemetry collected')) && vulns.length) summary = `Security Audit completed: ${vulns.length} risk finding(s) detected.`;
  const { os, versionInfo } = osSummaryFor(scan);

  return {
    scanned_at: scan.created_at || new Date().toISOString(),
    raw_config: rawConfig ? sanitizeConfig(rawConfig) : '',
    risk_level: getHighestRisk(scan.risk_level || (vulns.length ? 'HIGH' : 'LOW'), cachedRisk),
    summary: summary || 'No summary available',
    vulnerabilities: vulns,
    model_used: scan.model_used || 'cis-rules',
    raw_version: scan.raw_version || '',
    show_version: scan.raw_version || '',
    os_version: scan.raw_version || '',
    os_summary: os,
    version_info: versionInfo,
    os_cves: Array.isArray(scan.cve_details) ? scan.cve_details : [],
    target_firmware: scan.target_firmware || 'Not yet analyzed',
    eol_status: scan.eol_status || 'Not yet analyzed',
  };
}

export async function latestScanRef(deviceId: string): Promise<{ id: string; configuration_id: string | null; raw_version: string | null } | null> {
  const { data } = await supabase.from('scans').select('id, configuration_id, raw_version').eq('device_id', deviceId).order('created_at', { ascending: false }).limit(1).maybeSingle();
  return data;
}

export async function configText(device: Device, configurationId?: string | null): Promise<string> {
  if (device.last_config) return device.last_config;
  if (!configurationId) return '';
  const { data } = await supabase.from('configurations').select('raw_config, content').eq('id', configurationId).maybeSingle();
  return data?.raw_config || data?.content || '';
}
