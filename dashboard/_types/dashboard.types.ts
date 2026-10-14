// dashboard/_types/dashboard.types.ts
export type NavigationTab = 'inventory' | 'config' | 'version' | 'sandbox' | 'changes' | 'compliance' | 'remediation' | 'admin';

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
  // Credentials never reach the browser: they live in Supabase Vault and
  // the migration hides credential columns from browser roles.
  last_config?: string | null;
  raw_version?: string | null;
  os_version?: string | null;
  org_id?: string | null;
  is_mock?: boolean;
  collection_interval_minutes?: number | null;
  next_collection_at?: string | null;
  last_collection_error?: string | null;
  ssh_host_key_fingerprint?: string | null;
  ssh_host_key_pinned_at?: string | null;
}

export type Role = 'viewer' | 'operator' | 'admin';

export interface Membership {
  orgId: string;
  orgName: string;
  role: Role;
}

export interface Me {
  userId: string;
  email: string | null;
  memberships: Membership[];
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
  rule_id?: string | null;
  evidence?: string | null;
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

