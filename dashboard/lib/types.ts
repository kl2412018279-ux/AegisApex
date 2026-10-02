//C:\Users\hp\aiops-securewatch\dashboard\lib\types.ts
export type ConnectionStatus = 'online' | 'offline' | 'unreachable' | 'unknown';

// Flexible union accommodating UPPERCASE engine values and TitleCase display formats
export type RiskLevel =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL'
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low'
  | 'Informational';

export type Severity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low';

export type DeviceType =
  | 'cisco_ios'
  | 'cisco_ios_xe'
  | 'cisco_nxos'
  | 'cisco_xr'
  | 'juniper_junos'
  | 'fortinet_fortios'
  | 'arista_eos'
  | 'paloalto_panos'
  | 'generic';

export interface Device {
  id: string;
  hostname: string;
  management_ip: string;
  device_type: DeviceType;
  site_label: string | null;
  last_seen_at: string | null;
  connection_status: ConnectionStatus;
  created_at: string;
  updated_at: string;
}

export interface Configuration {
  id: string;
  device_id: string;
  sanitized_config: string;
  config_hash: string;
  pulled_at: string;
  lines_redacted: number;
  tokens?: Record<string, string>;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  rule_id?: string | null;
  cis_control?: string | null;
  title: string;
  severity: Severity;
  description: string | null;
  affected_config_line: string | null;
  remediation_cli: string | null;
  created_at: string;
}

export interface Scan {
  id: string;
  device_id: string;
  configuration_id: string;
  risk_score: number;
  risk_level: RiskLevel;
  summary: string | null;
  model_used: string;
  raw_ai_response: unknown;
  status: 'pending' | 'completed' | 'failed';
  scanned_at: string;
  vulnerabilities?: Vulnerability[];
}

export interface LatestDeviceScan {
  device_id: string;
  hostname: string;
  management_ip: string;
  connection_status: ConnectionStatus;
  scan_id: string | null;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  scanned_at: string | null;
}

export interface AiScanResult {
  risk_score: number;
  risk_level: RiskLevel;
  summary: string;
  vulnerabilities: Array<{
    rule_id?: string;
    cis_control?: string;
    title: string;
    severity: Severity;
    description: string;
    affected_config_line?: string;
    remediation_cli: string;
  }>;
}