// dashboard/_types/dashboard.types.ts
export type NavigationTab = 'inventory' | 'config' | 'version' | 'sandbox';

export interface AiCacheEntry {
  config: string;
  firmware: string;
  riskLevel?: string;
}

export interface Device {
  id: string;
  hostname: string;
  ip_address: string;
  vendor: string;
  netmiko_type: string;
  suppliers: { name: string } | null;
  connection_status: string;
  last_seen_at: string;
  risk_level: string;
  // FIX: ssh_user / ssh_pass removed from the client-facing Device type.
  // They were being fetched with the public anon key and held in browser
  // state (see the fix note in _hooks/useDashboard.ts). Credentials should
  // only ever exist server-side, resolved through the vault RPC the Python
  // agent already uses (agent/collector.py: fetch_decrypted_credentials).
  last_config?: string | null;
  raw_version?: string | null;
}

export interface Vulnerability {
  title?: string;
  name?: string;
  id?: string;
  severity?: string;
  risk_level?: string;
  description?: string;
  summary?: string;
  remediation?: string;
  remediation_cli?: string;
}

export interface ScanResult {
  scanned_at: string;
  raw_config: string;
  risk_level: string;
  summary: string;
  vulnerabilities: Vulnerability[];
  model_used: string;
  raw_version: string;
  show_version: string;
  os_version: string;
  os_summary: string;
  version_info: string;
  os_cves: any[];
  target_firmware: string;
  eol_status: string;
}

