// dashboard/lib/cisBenchmarks.ts
import { parseIndentedConfig, findBlocks, blockHas, blockFind, findUnusedEnabledInterfaces, ConfigNode } from './configParser';
import { sanitizeConfig } from './sanitizer';

export type VendorType =
  | 'cisco_ios'
  | 'cisco_nxos'
  | 'cisco_xr'
  | 'juniper'
  | 'arista'
  | 'fortinet'
  | 'paloalto'
  | 'huawei'
  | 'aruba_hpe'
  | 'dell_os10'
  | 'f5_tmsh'
  | 'nokia_sros'
  | 'vyos'
  | 'extreme_exos'
  | 'mikrotik'
  | 'generic';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface VendorRuleConfig {
  detectionKeys: string[];
  remediationCli: string;
}

export interface FrameworkMapping {
  nist80053: string[];
  pciDss4: string[];
  iso27001: string[];
}

export interface CISBenchmarkRule {
  ruleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  /** CIS Critical Security Controls v8 safeguard. */
  cisControl: string;
  vendors: Partial<Record<VendorType, VendorRuleConfig>>;
  /** When set, the rule is only evaluated for these platforms. */
  appliesTo?: VendorType[];
}

export interface ValidatedFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  remediationCli: string;
  cisControl?: string;
  frameworks?: FrameworkMapping;
  /** Redacted config excerpt or explanation of exactly what triggered the rule. */
  evidence?: string;
}

export const FRAMEWORK_LABELS: Record<keyof FrameworkMapping, string> = {
  nist80053: 'NIST SP 800-53 Rev. 5',
  pciDss4: 'PCI DSS v4.0',
  iso27001: 'ISO/IEC 27001:2022 Annex A',
};

export const RULE_FRAMEWORKS: Record<string, FrameworkMapping> = {
  'CIS-1.1': { nist80053: ['IA-5(1)', 'SC-28'], pciDss4: ['8.3.2'], iso27001: ['A.8.5', 'A.8.24'] },
  'CIS-1.2': { nist80053: ['AC-2', 'IA-2'], pciDss4: ['7.2.1', '8.2.1'], iso27001: ['A.5.15', 'A.8.5'] },
  'CIS-1.3': { nist80053: ['AC-17(2)', 'SC-8'], pciDss4: ['2.2.7'], iso27001: ['A.8.20', 'A.8.21'] },
  'CIS-1.4': { nist80053: ['CM-7', 'SC-8'], pciDss4: ['2.2.4', '2.2.7'], iso27001: ['A.8.20'] },
  'CIS-1.5': { nist80053: ['SC-8', 'SC-13'], pciDss4: ['2.2.7'], iso27001: ['A.8.24'] },
  'CIS-1.6': { nist80053: ['AC-11', 'AC-12'], pciDss4: ['8.2.8'], iso27001: ['A.8.5'] },
  'CIS-1.7': { nist80053: ['CM-6', 'IA-5'], pciDss4: ['2.2.2'], iso27001: ['A.8.9'] },
  'CIS-1.8': { nist80053: ['AU-4', 'AU-6', 'AU-9(2)'], pciDss4: ['10.2.1', '10.3.3'], iso27001: ['A.8.15'] },
  'CIS-1.9': { nist80053: ['AC-8'], pciDss4: [], iso27001: ['A.5.10'] },
  'CIS-1.10': { nist80053: ['AC-17', 'SC-7'], pciDss4: ['1.3.1'], iso27001: ['A.8.20', 'A.8.22'] },
  'CIS-1.11': { nist80053: ['AU-8'], pciDss4: ['10.6.1'], iso27001: ['A.8.17'] },
  'CIS-1.12': { nist80053: ['AU-8', 'SC-45(1)'], pciDss4: ['10.6.3'], iso27001: ['A.8.17'] },
  'CIS-1.13': { nist80053: ['IA-3', 'SC-8'], pciDss4: ['2.2.7', '8.3.2'], iso27001: ['A.8.20'] },
  'CIS-1.14': { nist80053: ['CM-7'], pciDss4: ['2.2.4'], iso27001: ['A.8.9'] },
  'CIS-1.15': { nist80053: ['IA-5(1)'], pciDss4: ['8.3.2'], iso27001: ['A.8.5'] },
  'CIS-1.16': { nist80053: ['AU-2', 'AU-12'], pciDss4: ['10.2.1.2'], iso27001: ['A.8.15'] },
  'CIS-1.17': { nist80053: ['SC-5'], pciDss4: [], iso27001: ['A.8.20'] },
  'CIS-1.18': { nist80053: ['CM-7'], pciDss4: ['2.2.4'], iso27001: ['A.8.20'] },
  'CIS-1.19': { nist80053: ['AC-7'], pciDss4: ['8.3.4'], iso27001: ['A.8.5'] },
};

export function detectVendor(input: string): VendorType {
  if (!input) return 'generic';
  const str = input.toLowerCase().trim();

  if (str.includes('cisco_xr') || str.includes('ios-xr') || str.includes('iosxr')) return 'cisco_xr';
  if (str.includes('nxos') || str.includes('nx-os') || str.includes('cisco_nxos')) return 'cisco_nxos';
  if (str.includes('ios') || str.includes('cisco')) return 'cisco_ios';
  if (str.includes('juniper') || str.includes('junos')) return 'juniper';
  if (str.includes('arista') || str.includes('eos')) return 'arista';
  if (str.includes('fortinet') || str.includes('fortigate') || str.includes('fortios')) return 'fortinet';
  if (str.includes('palo') || str.includes('pan') || str.includes('panos')) return 'paloalto';
  if (str.includes('huawei') || str.includes('vrp')) return 'huawei';
  if (str.includes('aruba') || str.includes('hp') || str.includes('hpe') || str.includes('comware')) return 'aruba_hpe';
  if (str.includes('dell') || str.includes('os10')) return 'dell_os10';
  if (str.includes('f5') || str.includes('tmsh') || str.includes('bigip')) return 'f5_tmsh';
  if (str.includes('nokia') || str.includes('sros') || str.includes('sr-os')) return 'nokia_sros';
  if (str.includes('vyos')) return 'vyos';
  if (str.includes('extreme') || str.includes('exos')) return 'extreme_exos';
  if (str.includes('mikrotik') || str.includes('routeros')) return 'mikrotik';

  return 'generic';
}

/**
 * Strips configuration comments and banner blocks to prevent false positive regex matches.
 */
function sanitizeConfigForScanning(rawConfig: string): string {
  if (!rawConfig) return '';
  return rawConfig
    .split('\n')
    .filter((line) => {
      const trimmed = line.trim();
      return (
        trimmed.length > 0 &&
        !trimmed.startsWith('!') &&
        !trimmed.startsWith('#') &&
        !trimmed.startsWith(';') &&
        !trimmed.startsWith('//')
      );
    })
    .join('\n');
}

export const CIS_BENCHMARK_MATRIX: CISBenchmarkRule[] = [
  {
    ruleId: 'CIS-1.1',
    title: 'Ensure Password Encryption is Enabled',
    description: 'Encrypt all plain text passwords stored in running configuration files.',
    severity: 'HIGH',
    cisControl: 'CIS Controls v8 3.11: Encrypt Sensitive Data at Rest',
    vendors: {
      cisco_ios: { detectionKeys: ['service password-encryption'], remediationCli: 'service password-encryption' },
      cisco_nxos: { detectionKeys: ['service password-encryption'], remediationCli: 'service password-encryption' },
      cisco_xr: { detectionKeys: ['service password-encryption'], remediationCli: 'service password-encryption' },
      arista: { detectionKeys: ['service password-encryption'], remediationCli: 'service password-encryption' },
      juniper: { detectionKeys: ['encrypted-password', '$9$'], remediationCli: 'set system login password format sha-512' },
      fortinet: { detectionKeys: ['private-encryption-key'], remediationCli: 'config system global\n set private-encryption-key enable\n end' },
      paloalto: { detectionKeys: ['phash'], remediationCli: 'set deviceconfig system password-hash sha512' },
      huawei: { detectionKeys: ['cipher'], remediationCli: 'set password-encryption type cipher' },
      aruba_hpe: { detectionKeys: ['password-encryption'], remediationCli: 'password-encryption' },
      dell_os10: { detectionKeys: ['service password-encryption'], remediationCli: 'service password-encryption' },
      f5_tmsh: { detectionKeys: ['encrypted'], remediationCli: 'modify sys user all encrypted-password' },
      nokia_sros: { detectionKeys: ['hash2'], remediationCli: 'configure system security password hash2' },
      vyos: { detectionKeys: ['encrypted-password'], remediationCli: 'set system login user admin authentication encrypted-password' },
      extreme_exos: { detectionKeys: ['encrypted'], remediationCli: 'configure account admin encrypted' },
      mikrotik: { detectionKeys: ['password='], remediationCli: '/user set [find name=admin] password="..."' },
      generic: { detectionKeys: ['password-encryption', 'encrypted'], remediationCli: 'Enable system password encryption' },
    },
  },
  {
    ruleId: 'CIS-1.2',
    title: 'Ensure AAA Authentication is Enabled',
    description: 'Enable Authentication, Authorization, and Accounting (AAA) services globally.',
    severity: 'CRITICAL',
    cisControl: 'CIS Controls v8 6.7: Centralize Access Control',
    vendors: {
      cisco_ios: { detectionKeys: ['aaa new-model', 'aaa group server', 'aaa authentication'], remediationCli: 'aaa new-model' },
      cisco_nxos: { detectionKeys: ['aaa group server', 'aaa authentication'], remediationCli: 'aaa group server tacacs+ TAC-SERVERS' },
      cisco_xr: { detectionKeys: ['aaa group server', 'aaa authentication'], remediationCli: 'aaa group server tacacs+ TAC-SERVERS' },
      arista: { detectionKeys: ['aaa authentication login'], remediationCli: 'aaa authentication login default local' },
      juniper: { detectionKeys: ['authentication-order', 'system login', 'tacplus', 'radius'], remediationCli: 'set system authentication-order [ tacplus radius local ]' },
      fortinet: { detectionKeys: ['config user radius', 'config user tacacs', 'config user group'], remediationCli: 'config user radius\n edit "AAA-Server"\n set server "10.0.0.1"\n set secret "secretKey"\n next\n end' },
      paloalto: { detectionKeys: ['authentication-profile'], remediationCli: 'set deviceconfig system authentication-profile AAA-Profile' },
      huawei: { detectionKeys: ['aaa'], remediationCli: 'aaa\n authentication-scheme default\n authentication-mode hwtacacs local' },
      aruba_hpe: { detectionKeys: ['aaa authentication login'], remediationCli: 'aaa authentication login default local' },
      dell_os10: { detectionKeys: ['aaa authentication login'], remediationCli: 'aaa authentication login default local' },
      f5_tmsh: { detectionKeys: ['auth source'], remediationCli: 'modify auth source radius' },
      nokia_sros: { detectionKeys: ['security aaa'], remediationCli: 'configure system security aaa authentication-order [ tacplus radius local ]' },
      vyos: { detectionKeys: ['radius-server', 'tacacs-server'], remediationCli: 'set system login radius-server 10.0.0.1 secret "secretKey"' },
      extreme_exos: { detectionKeys: ['enable aaa'], remediationCli: 'enable aaa' },
      mikrotik: { detectionKeys: ['/user aaa', 'radius'], remediationCli: '/user aaa set use-radius=yes' },
      generic: { detectionKeys: ['aaa', 'radius', 'tacacs'], remediationCli: 'Enable AAA authentication services' },
    },
  },
  {
    ruleId: 'CIS-1.3',
    title: 'Restrict Remote Transport to SSH Only',
    description: 'Disable unencrypted Telnet transport across administrative sessions.',
    severity: 'CRITICAL',
    cisControl: 'CIS Controls v8 4.6: Securely Manage Enterprise Assets and Software',
    vendors: {
      cisco_ios: { detectionKeys: ['transport input ssh'], remediationCli: 'line vty 0 15\n transport input ssh' },
      cisco_nxos: { detectionKeys: ['no feature telnet', 'transport input ssh'], remediationCli: 'no feature telnet\n line vty\n transport input ssh' },
      cisco_xr: { detectionKeys: ['transport input ssh'], remediationCli: 'line default\n transport input ssh' },
      arista: { detectionKeys: ['no management telnet', 'transport input ssh'], remediationCli: 'no management telnet\n line vty\n transport input ssh' },
      juniper: { detectionKeys: ['system services ssh'], remediationCli: 'set system services ssh\ndelete system services telnet' },
      fortinet: { detectionKeys: ['unset allowaccess telnet'], remediationCli: 'config system interface\n edit port1\n unset allowaccess telnet\n end' },
      paloalto: { detectionKeys: ['disable-telnet yes'], remediationCli: 'set deviceconfig system service disable-telnet yes' },
      huawei: { detectionKeys: ['undo telnet server enable', 'protocol inbound ssh'], remediationCli: 'undo telnet server enable\n user-interface vty 0 4\n protocol inbound ssh' },
      aruba_hpe: { detectionKeys: ['no telnet-server'], remediationCli: 'no telnet-server' },
      dell_os10: { detectionKeys: ['ip telnet server disable'], remediationCli: 'ip telnet server disable' },
      f5_tmsh: { detectionKeys: ['sys ssh enabled'], remediationCli: 'modify sys ssh enabled true' },
      nokia_sros: { detectionKeys: ['telnet shutdown'], remediationCli: 'configure system security telnet shutdown' },
      vyos: { detectionKeys: ['delete service telnet', 'service ssh'], remediationCli: 'delete service telnet' },
      extreme_exos: { detectionKeys: ['disable telnet'], remediationCli: 'disable telnet' },
      mikrotik: { detectionKeys: ['/ip service disable telnet'], remediationCli: '/ip service disable telnet' },
      generic: { detectionKeys: ['ssh', 'disable telnet'], remediationCli: 'Disable Telnet and enforce SSH transport' },
    },
  },
  {
    ruleId: 'CIS-1.4',
    title: 'Ensure HTTP Management Server is Disabled',
    description: 'Disable unencrypted HTTP web management service in favor of HTTPS.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 4.6: Securely Manage Enterprise Assets and Software',
    vendors: {
      cisco_ios: { detectionKeys: ['no ip http server'], remediationCli: 'no ip http server' },
      cisco_nxos: { detectionKeys: ['no feature http'], remediationCli: 'no feature http' },
      cisco_xr: { detectionKeys: ['no xml agent http'], remediationCli: 'no xml agent tty' },
      arista: { detectionKeys: ['no protocol http'], remediationCli: 'management api http-commands\n no protocol http' },
      juniper: { detectionKeys: ['web-management https'], remediationCli: 'delete system services web-management http\nset system services web-management https' },
      fortinet: { detectionKeys: ['unset allowaccess http'], remediationCli: 'config system interface\n edit port1\n unset allowaccess http\n end' },
      paloalto: { detectionKeys: ['disable-http yes'], remediationCli: 'set deviceconfig system service disable-http yes' },
      huawei: { detectionKeys: ['undo http server enable'], remediationCli: 'undo http server enable' },
      aruba_hpe: { detectionKeys: ['no web-management http'], remediationCli: 'no web-management http' },
      dell_os10: { detectionKeys: ['no ip http server'], remediationCli: 'no ip http server' },
      f5_tmsh: { detectionKeys: ['ssl-port 443'], remediationCli: 'modify sys httpd ssl-port 443' },
      nokia_sros: { detectionKeys: ['http shutdown'], remediationCli: 'configure system security http shutdown' },
      vyos: { detectionKeys: ['delete service https http'], remediationCli: 'delete service https http-redirect' },
      extreme_exos: { detectionKeys: ['disable web'], remediationCli: 'disable web' },
      mikrotik: { detectionKeys: ['/ip service disable www'], remediationCli: '/ip service disable www' },
      generic: { detectionKeys: ['no http', 'disable http'], remediationCli: 'Disable unencrypted HTTP management' },
    },
  },
  {
    ruleId: 'CIS-1.5',
    title: 'Ensure SSH Version 2 is Configured',
    description: 'Force SSH version 2 to prevent protocol downgrade vulnerabilities.',
    severity: 'HIGH',
    cisControl: 'CIS Controls v8 4.6: Securely Manage Enterprise Assets and Software',
    vendors: {
      cisco_ios: { detectionKeys: ['ip ssh version 2'], remediationCli: 'ip ssh version 2' },
      cisco_nxos: { detectionKeys: ['ssh version 2'], remediationCli: 'ssh version 2' },
      cisco_xr: { detectionKeys: ['ssh server v2'], remediationCli: 'ssh server v2' },
      arista: { detectionKeys: ['ip ssh version 2'], remediationCli: 'ip ssh version 2' },
      juniper: { detectionKeys: ['protocol-version v2'], remediationCli: 'set system services ssh protocol-version v2' },
      fortinet: { detectionKeys: ['ssh-v1 disable'], remediationCli: 'config system global\n set ssh-v1 disable\n end' },
      paloalto: { detectionKeys: ['ssh-v1 no'], remediationCli: 'set deviceconfig system service ssh-v1 no' },
      huawei: { detectionKeys: ['ssh server version v2'], remediationCli: 'ssh server version v2\n stelnet server enable' },
      aruba_hpe: { detectionKeys: ['ip ssh version 2'], remediationCli: 'ip ssh version 2' },
      dell_os10: { detectionKeys: ['ip ssh version 2'], remediationCli: 'ip ssh version 2' },
      f5_tmsh: { detectionKeys: ['include "Protocol 2"'], remediationCli: 'modify sys sshd include "Protocol 2"' },
      nokia_sros: { detectionKeys: ['version 2'], remediationCli: 'configure system security ssh version 2' },
      vyos: { detectionKeys: ['protocol-version v2'], remediationCli: 'set service ssh protocol-version v2' },
      extreme_exos: { detectionKeys: ['ssh version v2'], remediationCli: 'configure ssh version v2' },
      mikrotik: { detectionKeys: ['/ip service set ssh'], remediationCli: '/ip service set ssh port=22' },
      generic: { detectionKeys: ['ssh version 2', 'ssh v2'], remediationCli: 'Enforce SSH Protocol Version 2' },
    },
  },
  {
    ruleId: 'CIS-1.6',
    title: 'Configure EXEC Session Timeout',
    description: 'Automatically terminate inactive administrative terminal sessions.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 4.3: Configure Automatic Session Locking',
    vendors: {
      cisco_ios: { detectionKeys: ['exec-timeout'], remediationCli: 'line vty 0 15\n exec-timeout 10 0' },
      cisco_nxos: { detectionKeys: ['exec-timeout'], remediationCli: 'line vty\n exec-timeout 10' },
      cisco_xr: { detectionKeys: ['exec-timeout'], remediationCli: 'line default\n exec-timeout 10 0' },
      arista: { detectionKeys: ['exec-timeout'], remediationCli: 'line vty\n exec-timeout 10' },
      juniper: { detectionKeys: ['idle-timeout'], remediationCli: 'set system login idle-timeout 10' },
      fortinet: { detectionKeys: ['admintimeout'], remediationCli: 'config system global\n set admintimeout 10\n end' },
      paloalto: { detectionKeys: ['idle-timeout'], remediationCli: 'set deviceconfig setting management idle-timeout 10' },
      huawei: { detectionKeys: ['idle-timeout'], remediationCli: 'user-interface vty 0 4\n idle-timeout 10 0' },
      aruba_hpe: { detectionKeys: ['idle-timeout'], remediationCli: 'idle-timeout 10' },
      dell_os10: { detectionKeys: ['exec-timeout'], remediationCli: 'exec-timeout 10 0' },
      f5_tmsh: { detectionKeys: ['idle-timeout'], remediationCli: 'modify sys daemon-log-settings idle-timeout 600' },
      nokia_sros: { detectionKeys: ['idle-timeout'], remediationCli: 'configure system security session idle-timeout 10' },
      vyos: { detectionKeys: ['client-timeout'], remediationCli: 'set service ssh client-timeout 600' },
      extreme_exos: { detectionKeys: ['idle-timeout'], remediationCli: 'configure cli idle-timeout 10' },
      mikrotik: { detectionKeys: ['idle-timeout'], remediationCli: '/user settings set idle-timeout=10m' },
      generic: { detectionKeys: ['exec-timeout', 'idle-timeout'], remediationCli: 'Configure terminal session idle timeout' },
    },
  },
  {
    ruleId: 'CIS-1.7',
    title: 'Ensure Default SNMP Community Strings Are Removed',
    description: 'Default or guessable SNMP community strings ("public"/"private") permit unauthenticated read or write access to device management data and must be replaced with SNMPv3.',
    severity: 'HIGH',
    cisControl: 'CIS Controls v8 4.7: Manage Default Accounts on Enterprise Assets',
    vendors: {
      cisco_ios: { detectionKeys: ['snmp-server community public', 'snmp-server community private'], remediationCli: 'no snmp-server community public\nno snmp-server community private\nsnmp-server group SNMPv3GRP v3 priv' },
      cisco_nxos: { detectionKeys: ['snmp-server community public', 'snmp-server community private'], remediationCli: 'no snmp-server community public\nsnmp-server user admin SNMPv3GRP auth sha8 <key> priv aes-128 <key>' },
      cisco_xr: { detectionKeys: ['snmp-server community public', 'snmp-server community private'], remediationCli: 'no snmp-server community public\nsnmp-server group SNMPv3GRP v3 priv' },
      arista: { detectionKeys: ['snmp-server community public', 'snmp-server community private'], remediationCli: 'no snmp-server community public\nsnmp-server user admin SNMPv3GRP v3 auth sha <key> priv aes-128 <key>' },
      juniper: { detectionKeys: ['community public', 'community private'], remediationCli: 'delete snmp community public\nset snmp v3 usm local-engine user snmpv3user authentication-sha authentication-key <key> privacy-aes128 privacy-key <key>' },
      fortinet: { detectionKeys: ['community public', 'community private'], remediationCli: 'config system snmp community\n delete 1\nend\nconfig system snmp user\n edit "snmpv3user"\n set security-level auth-priv\n next\nend' },
      paloalto: { detectionKeys: ['version v2c', 'community public'], remediationCli: 'set deviceconfig system snmp-setting snmp-system version v3' },
      huawei: { detectionKeys: ['snmp-agent community'], remediationCli: 'undo snmp-agent community read public\nsnmp-agent usm-user v3 snmpv3user' },
      aruba_hpe: { detectionKeys: ['snmp-server community public', 'snmp-server community private'], remediationCli: 'no snmp-server community public\nsnmpv3 user snmpv3user auth sha <key> priv aes <key>' },
      dell_os10: { detectionKeys: ['snmp-server community public', 'snmp-server community private'], remediationCli: 'no snmp-server community public\nsnmp-server user snmpv3user auth sha <key> priv aes-128 <key>' },
      f5_tmsh: { detectionKeys: ['communities public', 'communities private'], remediationCli: 'modify sys snmp communities delete { public }' },
      nokia_sros: { detectionKeys: ['community "public"'], remediationCli: 'configure system security snmp community delete "public"' },
      vyos: { detectionKeys: ['community public', 'community private'], remediationCli: 'delete service snmp community public\nset service snmp v3 group default-group mode ro' },
      extreme_exos: { detectionKeys: ['snmp community public'], remediationCli: 'unconfigure snmp community public' },
      mikrotik: { detectionKeys: ['community=public'], remediationCli: '/snmp community set [find name=public] disabled=yes' },
      generic: { detectionKeys: ['community public', 'community private'], remediationCli: 'Remove default SNMP community strings and migrate to SNMPv3 with authPriv.' },
    },
  },
  {
    ruleId: 'CIS-1.8',
    title: 'Ensure Centralized Logging (Syslog) is Configured',
    description: 'Forward system and security events to a centralized syslog server so logs survive a device compromise and support cross-device correlation during an audit.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 8.9: Centralize Audit Logs',
    vendors: {
      cisco_ios: { detectionKeys: ['logging host', 'logging trap'], remediationCli: 'logging host 10.0.0.50\nlogging trap informational' },
      cisco_nxos: { detectionKeys: ['logging server'], remediationCli: 'logging server 10.0.0.50 6' },
      cisco_xr: { detectionKeys: ['logging host'], remediationCli: 'logging 10.0.0.50 vrf default severity info' },
      arista: { detectionKeys: ['logging host'], remediationCli: 'logging host 10.0.0.50' },
      juniper: { detectionKeys: ['system syslog host'], remediationCli: 'set system syslog host 10.0.0.50 any notice' },
      fortinet: { detectionKeys: ['config log syslogd setting'], remediationCli: 'config log syslogd setting\n set status enable\n set server "10.0.0.50"\nend' },
      paloalto: { detectionKeys: ['syslog server'], remediationCli: 'set shared log-settings syslog SYSLOG-PROFILE server LOG-SERVER server 10.0.0.50 transport UDP port 514' },
      huawei: { detectionKeys: ['info-center loghost'], remediationCli: 'info-center loghost 10.0.0.50' },
      aruba_hpe: { detectionKeys: ['logging host'], remediationCli: 'logging 10.0.0.50' },
      dell_os10: { detectionKeys: ['logging server'], remediationCli: 'logging server 10.0.0.50' },
      f5_tmsh: { detectionKeys: ['syslog remote-servers'], remediationCli: 'modify sys syslog remote-servers add { remote1 { host 10.0.0.50 } }' },
      nokia_sros: { detectionKeys: ['log syslog'], remediationCli: 'configure log syslog 1 address 10.0.0.50' },
      vyos: { detectionKeys: ['system syslog host'], remediationCli: 'set system syslog host 10.0.0.50 facility all level info' },
      extreme_exos: { detectionKeys: ['configure syslog'], remediationCli: 'configure syslog add 10.0.0.50 local0' },
      mikrotik: { detectionKeys: ['/system logging action'], remediationCli: '/system logging action set [find name=remote] remote=10.0.0.50' },
      generic: { detectionKeys: ['logging host', 'syslog'], remediationCli: 'Configure a centralized syslog server for audit/event log forwarding.' },
    },
  },
  {
    ruleId: 'CIS-1.9',
    title: 'Ensure a Login/Warning Banner is Configured',
    description: 'An unauthorized-access warning banner must be presented at login for legal notice and deterrence purposes.',
    severity: 'LOW',
    cisControl: 'CIS Controls v8 4.1: Establish and Maintain a Secure Configuration Process',
    vendors: {
      cisco_ios: { detectionKeys: ['banner motd', 'banner login'], remediationCli: 'banner motd #Authorized Access Only#' },
      cisco_nxos: { detectionKeys: ['banner motd'], remediationCli: 'banner motd #Authorized Access Only#' },
      cisco_xr: { detectionKeys: ['banner motd', 'banner login'], remediationCli: 'banner motd #Authorized Access Only#' },
      arista: { detectionKeys: ['banner motd', 'banner login'], remediationCli: 'banner motd\nAuthorized Access Only\nEOF' },
      juniper: { detectionKeys: ['system login message'], remediationCli: 'set system login message "Authorized Access Only"' },
      fortinet: { detectionKeys: ['pre-login-banner enable'], remediationCli: 'config system global\n set pre-login-banner enable\nend' },
      paloalto: { detectionKeys: ['login-banner'], remediationCli: 'set deviceconfig system login-banner "Authorized Access Only"' },
      huawei: { detectionKeys: ['header login'], remediationCli: 'header login information "Authorized Access Only"' },
      aruba_hpe: { detectionKeys: ['banner motd'], remediationCli: 'banner motd "Authorized Access Only"' },
      dell_os10: { detectionKeys: ['banner motd'], remediationCli: 'banner motd "Authorized Access Only"' },
      f5_tmsh: { detectionKeys: ['login banner'], remediationCli: 'modify sys global-settings gui-setup disabled\nmodify auth banner-text "Authorized Access Only"' },
      nokia_sros: { detectionKeys: ['login-banner'], remediationCli: 'configure system login-control pre-login-message "Authorized Access Only"' },
      vyos: { detectionKeys: ['login banner'], remediationCli: 'set system login banner pre-login "Authorized Access Only"' },
      extreme_exos: { detectionKeys: ['banner'], remediationCli: 'configure banner "Authorized Access Only"' },
      mikrotik: { detectionKeys: ['/system note'], remediationCli: '/system note set note="Authorized Access Only" show-at-login=yes' },
      generic: { detectionKeys: ['banner'], remediationCli: 'Configure an unauthorized-access warning banner.' },
    },
  },
  {
    ruleId: 'CIS-1.10',
    title: 'Restrict Remote Management Access by ACL',
    description: 'Administrative/VTY access must be restricted to an explicit allow-list of trusted management source addresses, not open to any reachable address.',
    severity: 'HIGH',
    cisControl: 'CIS Controls v8 12.3: Securely Manage Network Infrastructure',
    vendors: {
      cisco_ios: { detectionKeys: ['access-class'], remediationCli: 'ip access-list standard MGMT-ACL\n permit 10.0.0.0 0.0.0.255\nline vty 0 15\n access-class MGMT-ACL in' },
      cisco_nxos: { detectionKeys: ['access-class'], remediationCli: 'ip access-list MGMT-ACL\n permit ip 10.0.0.0/24 any\nline vty\n access-class MGMT-ACL in' },
      cisco_xr: { detectionKeys: ['access-class'], remediationCli: 'line default\n access-class ingress MGMT-ACL' },
      arista: { detectionKeys: ['access-class'], remediationCli: 'ip access-list MGMT-ACL\n permit ip 10.0.0.0/24 any\nline vty\n access-class MGMT-ACL in' },
      juniper: { detectionKeys: ['firewall filter', 'protect-re'], remediationCli: 'set firewall family inet filter PROTECT-RE term mgmt from source-address 10.0.0.0/24\nset interfaces lo0 unit 0 family inet filter input PROTECT-RE' },
      fortinet: { detectionKeys: ['trusthost'], remediationCli: 'config system admin\n edit admin\n set trusthost1 10.0.0.0 255.255.255.0\n next\nend' },
      paloalto: { detectionKeys: ['permitted-ip'], remediationCli: 'set deviceconfig system permitted-ip 10.0.0.0/24' },
      huawei: { detectionKeys: ['acl', 'user-interface vty'], remediationCli: 'acl 2001\n rule permit source 10.0.0.0 0.0.0.255\nuser-interface vty 0 4\n acl 2001 inbound' },
      aruba_hpe: { detectionKeys: ['access-list', 'secure-mgmt'], remediationCli: 'ip access-list MGMT-ACL\n permit 10.0.0.0/24\napply access-list ip MGMT-ACL vlan 1 in' },
      dell_os10: { detectionKeys: ['access-class'], remediationCli: 'ip access-list MGMT-ACL\n permit ip 10.0.0.0/24 any\nline vty\n access-class MGMT-ACL in' },
      f5_tmsh: { detectionKeys: ['allow-service'], remediationCli: 'modify net self-allow defaults add { tcp:22 }\nmodify sys management-ip-allow add { 10.0.0.0/24 }' },
      nokia_sros: { detectionKeys: ['management-access-filter'], remediationCli: 'configure system security management-access-filter default-action deny\nconfigure system security management-access-filter entry 1 match src-ip 10.0.0.0/24' },
      vyos: { detectionKeys: ['firewall', 'source-address'], remediationCli: 'set service ssh listen-address 10.0.0.1\nset firewall name MGMT-IN rule 10 source address 10.0.0.0/24' },
      extreme_exos: { detectionKeys: ['configure access-list'], remediationCli: 'configure access-list MGMT-ACL 10 permit 10.0.0.0/24' },
      mikrotik: { detectionKeys: ['/ip service set', 'address='], remediationCli: '/ip service set ssh address=10.0.0.0/24' },
      generic: { detectionKeys: ['access-class', 'trusthost', 'permitted-ip'], remediationCli: 'Restrict administrative management access to a trusted source-address allow-list.' },
    },
  },
  {
    ruleId: 'CIS-1.11',
    title: 'Ensure NTP Time Synchronization is Configured',
    description: 'Configure an authoritative NTP time source so log timestamps are accurate and correlate correctly across devices during an incident or audit.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 8.4: Standardize Time Synchronization',
    vendors: {
      cisco_ios: { detectionKeys: ['ntp server'], remediationCli: 'ntp server 10.0.0.1' },
      cisco_nxos: { detectionKeys: ['ntp server'], remediationCli: 'ntp server 10.0.0.1 use-vrf default' },
      cisco_xr: { detectionKeys: ['ntp server'], remediationCli: 'ntp server 10.0.0.1' },
      arista: { detectionKeys: ['ntp server'], remediationCli: 'ntp server 10.0.0.1' },
      juniper: { detectionKeys: ['system ntp server'], remediationCli: 'set system ntp server 10.0.0.1' },
      fortinet: { detectionKeys: ['config system ntp'], remediationCli: 'config system ntp\n set ntpsync enable\n set server-mode enable\nend' },
      paloalto: { detectionKeys: ['ntp-servers'], remediationCli: 'set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.0.0.1' },
      huawei: { detectionKeys: ['ntp-service unicast-server'], remediationCli: 'ntp-service unicast-server 10.0.0.1' },
      aruba_hpe: { detectionKeys: ['ntp server'], remediationCli: 'ntp server 10.0.0.1' },
      dell_os10: { detectionKeys: ['ntp server'], remediationCli: 'ntp server 10.0.0.1' },
      f5_tmsh: { detectionKeys: ['ntp servers'], remediationCli: 'modify sys ntp servers add { 10.0.0.1 }' },
      nokia_sros: { detectionKeys: ['system time ntp'], remediationCli: 'configure system time ntp server 10.0.0.1' },
      vyos: { detectionKeys: ['system ntp server'], remediationCli: 'set system ntp server 10.0.0.1' },
      extreme_exos: { detectionKeys: ['configure sntp-client'], remediationCli: 'configure sntp-client primary 10.0.0.1\nenable sntp-client' },
      mikrotik: { detectionKeys: ['/system ntp client'], remediationCli: '/system ntp client set enabled=yes primary-ntp=10.0.0.1' },
      generic: { detectionKeys: ['ntp server', 'ntp-service'], remediationCli: 'Configure an authoritative NTP time source.' },
    },
  },
  {
    ruleId: 'CIS-1.12',
    title: 'Ensure NTP Authentication is Enabled',
    description: 'Unauthenticated NTP lets an on-path attacker skew the device clock, corrupting log timelines and certificate validity checks.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 8.4: Standardize Time Synchronization',
    vendors: {
      cisco_ios: { detectionKeys: ['ntp authenticate'], remediationCli: 'ntp authentication-key 1 md5 <key>\nntp authenticate\nntp trusted-key 1\nntp server 10.0.0.1 key 1' },
      cisco_nxos: { detectionKeys: ['ntp authenticate'], remediationCli: 'ntp authentication-key 1 md5 <key>\nntp authenticate\nntp trusted-key 1\nntp server 10.0.0.1 key 1' },
      cisco_xr: { detectionKeys: ['authenticate'], remediationCli: 'ntp\n authentication-key 1 md5 <key>\n authenticate\n trusted-key 1\n server 10.0.0.1 key 1' },
      arista: { detectionKeys: ['ntp authenticate'], remediationCli: 'ntp authentication-key 1 md5 <key>\nntp authenticate\nntp trusted-key 1\nntp server 10.0.0.1 key 1' },
      dell_os10: { detectionKeys: ['ntp authenticate'], remediationCli: 'ntp authentication-key 1 md5 <key>\nntp authenticate\nntp trusted-key 1' },
      juniper: { detectionKeys: ['authentication-key'], remediationCli: 'set system ntp authentication-key 1 type sha256 value <key>\nset system ntp trusted-key 1\nset system ntp server 10.0.0.1 key 1' },
      huawei: { detectionKeys: ['ntp-service authentication enable'], remediationCli: 'ntp-service authentication enable\nntp-service authentication-keyid 1 authentication-mode hmac-sha256 <key>\nntp-service reliable authentication-keyid 1' },
      fortinet: { detectionKeys: ['set authentication enable'], remediationCli: 'config system ntp\n config ntpserver\n  edit 1\n   set authentication enable\n   set key <key>\n   set key-id 1\n  next\n end\nend' },
      paloalto: { detectionKeys: ['symmetric-key'], remediationCli: 'set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key key-id 1 algorithm sha1 authentication-key <key>' },
      generic: { detectionKeys: ['ntp authenticate', 'authentication-key'], remediationCli: 'Enable NTP authentication with a trusted key for every configured server.' },
    },
    appliesTo: ['cisco_ios', 'cisco_nxos', 'cisco_xr', 'arista', 'dell_os10', 'juniper', 'huawei', 'fortinet', 'paloalto'],
  },
  {
    ruleId: 'CIS-1.13',
    title: 'Ensure SNMPv1/v2c Community Access is Disabled',
    description: 'SNMPv1/v2c send community strings in cleartext and provide no per-user authentication. Use SNMPv3 with authPriv instead.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 4.6: Securely Manage Enterprise Assets and Software',
    vendors: {
      cisco_ios: { detectionKeys: ['snmp-server community'], remediationCli: 'no snmp-server community <community>\nsnmp-server group SNMPv3GRP v3 priv\nsnmp-server user snmpv3user SNMPv3GRP v3 auth sha <key> priv aes 128 <key>' },
      cisco_nxos: { detectionKeys: ['snmp-server community'], remediationCli: 'no snmp-server community <community>\nsnmp-server user snmpv3user network-operator auth sha <key> priv aes-128 <key>' },
      cisco_xr: { detectionKeys: ['snmp-server community'], remediationCli: 'no snmp-server community <community>\nsnmp-server group SNMPv3GRP v3 priv' },
      arista: { detectionKeys: ['snmp-server community'], remediationCli: 'no snmp-server community <community>\nsnmp-server user snmpv3user SNMPv3GRP v3 auth sha <key> priv aes <key>' },
      dell_os10: { detectionKeys: ['snmp-server community'], remediationCli: 'no snmp-server community <community>\nsnmp-server user snmpv3user SNMPv3GRP 3 auth sha <key> priv aes <key>' },
      aruba_hpe: { detectionKeys: ['snmp-server community'], remediationCli: 'no snmp-server community <community>\nsnmpv3 user snmpv3user auth sha <key> priv aes <key>' },
      juniper: { detectionKeys: ['snmp community'], remediationCli: 'delete snmp community <community>\nset snmp v3 usm local-engine user snmpv3user authentication-sha authentication-key <key> privacy-aes128 privacy-key <key>' },
      vyos: { detectionKeys: ['snmp community'], remediationCli: 'delete service snmp community <community>\nset service snmp v3 user snmpv3user auth type sha' },
      huawei: { detectionKeys: ['snmp-agent community'], remediationCli: 'undo snmp-agent community <community>\nsnmp-agent sys-info version v3\nsnmp-agent usm-user v3 snmpv3user' },
      fortinet: { detectionKeys: ['config system snmp community'], remediationCli: 'config system snmp community\n delete <id>\nend' },
      paloalto: { detectionKeys: ['version v2c'], remediationCli: 'set deviceconfig system snmp-setting access-setting version v3' },
      mikrotik: { detectionKeys: ['/snmp community'], remediationCli: '/snmp community set [find] disabled=yes' },
      generic: { detectionKeys: ['snmp-server community', 'snmp community'], remediationCli: 'Disable SNMPv1/v2c communities and migrate to SNMPv3 authPriv.' },
    },
    appliesTo: ['cisco_ios', 'cisco_nxos', 'cisco_xr', 'arista', 'dell_os10', 'aruba_hpe', 'juniper', 'vyos', 'huawei', 'fortinet', 'paloalto', 'mikrotik'],
  },
  {
    ruleId: 'CIS-1.14',
    title: 'Disable Unnecessary Legacy Services',
    description: 'TCP/UDP small servers, finger, PAD and similar legacy services widen the attack surface and are not needed on a modern network device.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 4.8: Uninstall or Disable Unnecessary Services',
    vendors: {
      cisco_ios: { detectionKeys: ['service tcp-small-servers', 'service udp-small-servers', 'ip finger', 'service pad'], remediationCli: 'no service tcp-small-servers\nno service udp-small-servers\nno ip finger\nno service pad\nno ip bootp server' },
      cisco_xr: { detectionKeys: ['service ipv4 tcp-small-servers', 'service ipv4 udp-small-servers'], remediationCli: 'no service ipv4 tcp-small-servers\nno service ipv4 udp-small-servers' },
    },
    appliesTo: ['cisco_ios', 'cisco_xr'],
  },
  {
    ruleId: 'CIS-1.15',
    title: 'Ensure Strong Password Hashing for Local Accounts',
    description: 'Plaintext, type 7 (reversible) and type 5 (MD5) passwords can be recovered offline. Use type 8 (PBKDF2) or type 9 (scrypt) secrets.',
    severity: 'HIGH',
    cisControl: 'CIS Controls v8 5.2: Use Unique Passwords',
    vendors: {
      cisco_ios: { detectionKeys: ['enable password', 'password 7', 'secret 5'], remediationCli: 'no enable password\nenable algorithm-type scrypt secret <password>\nusername <user> privilege 15 algorithm-type scrypt secret <password>' },
      arista: { detectionKeys: ['secret 0', 'nopassword'], remediationCli: 'username <user> privilege 15 role network-admin secret sha512 <password>' },
    },
    appliesTo: ['cisco_ios', 'arista'],
  },
  {
    ruleId: 'CIS-1.16',
    title: 'Ensure AAA Accounting is Enabled',
    description: 'Command and session accounting create an attributable record of administrative changes, which is required to investigate an incident.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 8.5: Collect Detailed Audit Logs',
    vendors: {
      cisco_ios: { detectionKeys: ['aaa accounting'], remediationCli: 'aaa accounting exec default start-stop group tacacs+\naaa accounting commands 15 default start-stop group tacacs+' },
      cisco_nxos: { detectionKeys: ['aaa accounting'], remediationCli: 'aaa accounting default group TAC-SERVERS' },
      cisco_xr: { detectionKeys: ['aaa accounting'], remediationCli: 'aaa accounting exec default start-stop group tacacs+\naaa accounting commands default start-stop group tacacs+' },
      arista: { detectionKeys: ['aaa accounting'], remediationCli: 'aaa accounting exec default start-stop group tacacs+\naaa accounting commands all default start-stop group tacacs+' },
      dell_os10: { detectionKeys: ['aaa accounting'], remediationCli: 'aaa accounting commands all default start-stop group tacacs+' },
      juniper: { detectionKeys: ['system accounting', 'accounting events'], remediationCli: 'set system accounting events [ login change-log interactive-commands ]\nset system accounting destination tacplus' },
      huawei: { detectionKeys: ['accounting-scheme'], remediationCli: 'aaa\n accounting-scheme ACCT\n  accounting-mode hwtacacs' },
    },
    appliesTo: ['cisco_ios', 'cisco_nxos', 'cisco_xr', 'arista', 'dell_os10', 'juniper', 'huawei'],
  },
  {
    ruleId: 'CIS-1.17',
    title: 'Ensure Control-Plane Protection is Configured',
    description: 'Without control-plane policing or a loopback filter, a flood of traffic to the device itself can exhaust the CPU and take down routing and management.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 12.3: Securely Manage Network Infrastructure',
    vendors: {
      cisco_ios: { detectionKeys: ['control-plane', 'service-policy input'], remediationCli: 'control-plane\n service-policy input COPP-POLICY' },
      cisco_nxos: { detectionKeys: ['copp profile'], remediationCli: 'copp profile strict' },
      juniper: { detectionKeys: ['lo0', 'filter input'], remediationCli: 'set interfaces lo0 unit 0 family inet filter input PROTECT-RE' },
    },
    appliesTo: ['cisco_ios', 'cisco_nxos', 'juniper'],
  },
  {
    ruleId: 'CIS-1.18',
    title: 'Shut Down Unused Interfaces',
    description: 'Ports with no description, addressing or VLAN assignment that are still enabled give anyone with physical access a live connection into the default VLAN.',
    severity: 'LOW',
    cisControl: 'CIS Controls v8 4.8: Uninstall or Disable Unnecessary Services',
    vendors: {
      cisco_ios: { detectionKeys: [], remediationCli: 'interface <unused-interface>\n description UNUSED\n switchport access vlan 999\n shutdown' },
      cisco_nxos: { detectionKeys: [], remediationCli: 'interface <unused-interface>\n description UNUSED\n shutdown' },
      arista: { detectionKeys: [], remediationCli: 'interface <unused-interface>\n description UNUSED\n shutdown' },
      dell_os10: { detectionKeys: [], remediationCli: 'interface <unused-interface>\n description UNUSED\n shutdown' },
    },
    appliesTo: ['cisco_ios', 'cisco_nxos', 'arista', 'dell_os10'],
  },
  {
    ruleId: 'CIS-1.19',
    title: 'Ensure Login Brute-Force Protection is Configured',
    description: 'Without a login lockout or back-off, an attacker who can reach the management plane can guess passwords at full speed.',
    severity: 'MEDIUM',
    cisControl: 'CIS Controls v8 6.7: Centralize Access Control',
    vendors: {
      cisco_ios: { detectionKeys: ['login block-for'], remediationCli: 'login block-for 120 attempts 5 within 60\nlogin on-failure log' },
      juniper: { detectionKeys: ['retry-options'], remediationCli: 'set system login retry-options tries-before-disconnect 3 backoff-threshold 2 lockout-period 10' },
      fortinet: { detectionKeys: ['admin-lockout-threshold'], remediationCli: 'config system global\n set admin-lockout-threshold 3\n set admin-lockout-duration 300\nend' },
      paloalto: { detectionKeys: ['failed-attempts'], remediationCli: 'set mgt-config password-complexity enabled yes\nset shared authentication-profile <profile> lockout failed-attempts 5 lockout-time 10' },
    },
    appliesTo: ['cisco_ios', 'juniper', 'fortinet', 'paloalto'],
  },
];


const hasAnyKey = (config: string, keys: string[]): boolean => {
  const lower = config.toLowerCase();
  return keys.some((k) => lower.includes(k.toLowerCase()));
};

const CISCO_LINE_STYLE: VendorType[] = ['cisco_ios', 'cisco_xr', 'arista', 'dell_os10'];

interface RuleOutcome {
  violated: boolean;
  evidence?: string;
}

const ok: RuleOutcome = { violated: false };
const fail = (evidence?: string): RuleOutcome => ({ violated: true, evidence });

interface EvalContext {
  cfg: string;
  tree: ConfigNode[];
  vtyBlocks: ConfigNode[];
}

function evaluateRule(
  rule: CISBenchmarkRule,
  vendor: VendorType,
  ctx: EvalContext,
  vConfig: VendorRuleConfig
): RuleOutcome {
  const { cfg, tree, vtyBlocks } = ctx;
  const keyFallback = (): RuleOutcome =>
    hasAnyKey(cfg, vConfig.detectionKeys) ? ok : fail(`None of: ${vConfig.detectionKeys.join(', ')}`);

  switch (rule.ruleId) {
    case 'CIS-1.1': {
      if (vendor.startsWith('cisco') || vendor === 'arista' || vendor === 'dell_os10') {
        if (/no\s+service\s+password-encryption/i.test(cfg)) return fail('no service password-encryption');
        return /service\s+password-encryption/i.test(cfg) ? ok : fail('service password-encryption is not configured');
      }
      if (vendor === 'juniper') return /encrypted-password|\$9\$|\$6\$/i.test(cfg) ? ok : fail('No encrypted-password entries found');
      if (vendor === 'vyos') {
        if (/plaintext-password/i.test(cfg)) return fail('plaintext-password is configured');
        return /encrypted-password/i.test(cfg) ? ok : fail('No encrypted-password entries found');
      }
      if (vendor === 'extreme_exos') {
        return /configure\s+account.*password/i.test(cfg) && !/configure\s+account.*encrypted/i.test(cfg)
          ? fail('Account password configured without encryption')
          : ok;
      }
      return keyFallback();
    }

    case 'CIS-1.2': {
      const re: Partial<Record<VendorType, RegExp>> = {
        arista: /aaa\s+authentication\s+login/i,
        dell_os10: /aaa\s+authentication\s+login/i,
        aruba_hpe: /aaa\s+authentication\s+login/i,
        juniper: /(authentication-order|tacplus|radius-server)/i,
        fortinet: /config\s+user\s+(radius|tacacs|group)/i,
        paloalto: /authentication-profile/i,
        huawei: /\baaa\b/i,
        f5_tmsh: /auth\s+source/i,
        nokia_sros: /security\s+aaa|authentication-order/i,
        vyos: /(radius|tacacs)/i,
        extreme_exos: /enable\s+aaa/i,
        mikrotik: /use-radius\s*=\s*yes/i,
      };
      if (vendor.startsWith('cisco')) {
        return /aaa\s+(new-model|group|authentication)/i.test(cfg) ? ok : fail('No aaa new-model / aaa authentication configured');
      }
      const r = re[vendor];
      if (r) return r.test(cfg) ? ok : fail('No central AAA configuration found');
      return keyFallback();
    }

    case 'CIS-1.3': {
      if (vendor === 'cisco_ios' && vtyBlocks.length > 0) {
        const bad = vtyBlocks.filter((b) => {
          const transport = blockFind(b, /^transport\s+input\b/i);
          return !transport || !/^transport\s+input\s+ssh\s*$/i.test(transport);
        });
        return bad.length
          ? fail(bad.map((b) => `${b.text}: ${blockFind(b, /^transport\s+input\b/i) || 'no transport input (defaults may allow telnet)'}`).join('; '))
          : ok;
      }
      if (vendor === 'cisco_nxos') return /^\s*feature\s+telnet/im.test(cfg) ? fail('feature telnet') : ok;
      if (vendor === 'arista') {
        const telnet = findBlocks(tree, /^management\s+telnet/i);
        return telnet.some((b) => !blockHas(b, /^shutdown$/i)) ? fail('management telnet is not shut down') : ok;
      }
      if (vendor.startsWith('cisco') || vendor === 'dell_os10') {
        if (/transport\s+input\s+.*telnet|transport\s+input\s+all/i.test(cfg)) return fail('transport input permits telnet');
        if (vendor === 'dell_os10') return /ip\s+telnet\s+server\s+enable/i.test(cfg) ? fail('ip telnet server enable') : ok;
        return /transport\s+input\s+ssh\b/i.test(cfg) ? ok : fail('No transport input ssh found');
      }
      if (vendor === 'juniper') {
        if (/system\s+services\s+telnet/i.test(cfg)) return fail('system services telnet');
        return /system\s+services\s+ssh/i.test(cfg) ? ok : fail('system services ssh not configured');
      }
      if (vendor === 'fortinet') return /set\s+allowaccess.*\btelnet\b/i.test(cfg) ? fail('allowaccess includes telnet') : ok;
      if (vendor === 'paloalto') return /disable-telnet\s+yes/i.test(cfg) ? ok : fail('disable-telnet yes not set');
      if (vendor === 'huawei') {
        if (/^\s*telnet\s+server\s+enable/im.test(cfg)) return fail('telnet server enable');
        return /protocol\s+inbound\s+ssh/i.test(cfg) ? ok : fail('VTY not restricted to protocol inbound ssh');
      }
      if (vendor === 'aruba_hpe') return /^\s*telnet-server/im.test(cfg) && !/no\s+telnet-server/i.test(cfg) ? fail('telnet-server enabled') : ok;
      if (vendor === 'vyos') {
        if (/service\s+telnet/i.test(cfg)) return fail('service telnet');
        return /service\s+ssh/i.test(cfg) ? ok : fail('service ssh not configured');
      }
      if (vendor === 'extreme_exos') return /\benable\s+telnet\b/i.test(cfg) || !/\bdisable\s+telnet\b/i.test(cfg) ? fail('telnet not disabled') : ok;
      if (vendor === 'mikrotik') return /\/ip\s+service.*telnet/i.test(cfg) && !/disable\s+telnet|telnet.*disabled=yes/i.test(cfg) ? fail('telnet service enabled') : ok;
      return /telnet/i.test(cfg) && !/no\s+telnet|disable\s+telnet|telnet\s+shutdown/i.test(cfg) ? fail('telnet appears enabled') : ok;
    }

    case 'CIS-1.4': {
      if (vendor.startsWith('cisco') || vendor === 'dell_os10') {
        if (vendor === 'cisco_nxos') return /^\s*feature\s+http-server/im.test(cfg) ? fail('feature http-server') : ok;
        return /^\s*ip\s+http\s+server\b/im.test(cfg) ? fail('ip http server') : ok;
      }
      if (vendor === 'arista') return /^\s*protocol\s+http\b/im.test(cfg) && !/no\s+protocol\s+http\b/i.test(cfg) ? fail('protocol http') : ok;
      if (vendor === 'juniper') return /web-management\s+http\b/i.test(cfg) ? fail('web-management http') : ok;
      if (vendor === 'fortinet') return /set\s+allowaccess.*\bhttp\b/i.test(cfg) ? fail('allowaccess includes http') : ok;
      if (vendor === 'paloalto') return /disable-http\s+yes/i.test(cfg) ? ok : fail('disable-http yes not set');
      if (vendor === 'huawei') return /^\s*http\s+server\s+enable/im.test(cfg) ? fail('http server enable') : ok;
      if (vendor === 'aruba_hpe') return /^\s*web-management\s+http/im.test(cfg) || /https-server\s+http-enable/i.test(cfg) && !/no\s+https-server\s+http-enable/i.test(cfg) ? fail('HTTP management enabled') : ok;
      if (vendor === 'extreme_exos') return /\benable\s+web\b/i.test(cfg) && !/\bdisable\s+web\b/i.test(cfg) ? fail('enable web') : ok;
      if (vendor === 'mikrotik') return /\/ip\s+service.*www\b/i.test(cfg) && !/disable\s+www|www.*disabled=yes/i.test(cfg) ? fail('www service enabled') : ok;
      return /\bhttp\s+server\b/i.test(cfg) && !/no\s+http|disable\s+http|undo\s+http/i.test(cfg) ? fail('http server appears enabled') : ok;
    }

    case 'CIS-1.5': {
      if (vendor.startsWith('cisco') || vendor === 'arista' || vendor === 'dell_os10' || vendor === 'aruba_hpe') {
        if (vendor === 'cisco_nxos' || vendor === 'arista') return /ssh\s+version\s+1\b/i.test(cfg) ? fail('ssh version 1') : ok;
        return /(ip\s+ssh\s+version\s+2|ssh\s+version\s+2|ssh\s+server\s+v2)/i.test(cfg) ? ok : fail('SSH version 2 is not enforced');
      }
      if (vendor === 'juniper' || vendor === 'vyos') return /protocol-version\s+v1/i.test(cfg) ? fail('protocol-version v1') : ok;
      if (vendor === 'huawei' || vendor === 'extreme_exos') return /ssh\s+(server\s+)?(compatible-ssh1x\s+enable|version\s+v?1\b)/i.test(cfg) ? fail('SSHv1 compatibility enabled') : ok;
      if (vendor === 'fortinet') return /ssh-v1\s+enable/i.test(cfg) ? fail('ssh-v1 enable') : ok;
      if (vendor === 'paloalto') return /ssh-v1\s+yes/i.test(cfg) ? fail('ssh-v1 yes') : ok;
      return /ssh.*(version\s+1\b|v1\b)/i.test(cfg) ? fail('SSHv1 appears enabled') : ok;
    }

    case 'CIS-1.6': {
      const zero = cfg.match(/exec-timeout\s+0(\s+0)?\s*$|admintimeout\s+0\b|idle-timeout\s+0\b|client-timeout\s+0\b/im);
      if (zero) return fail(`Session timeout disabled: ${zero[0].trim()}`);
      if (vendor === 'cisco_ios' && vtyBlocks.length > 0) {
        const bad = vtyBlocks.filter((b) => !blockFind(b, /^exec-timeout\s+([1-9]|0\s+[1-9])/i));
        return bad.length ? fail(bad.map((b) => `${b.text}: no explicit exec-timeout`).join('; ')) : ok;
      }
      if (vendor.startsWith('cisco') || vendor === 'arista' || vendor === 'dell_os10') return /exec-timeout\s+[1-9]/i.test(cfg) ? ok : fail('No exec-timeout configured');
      if (['juniper', 'paloalto', 'huawei', 'aruba_hpe', 'extreme_exos'].includes(vendor)) return /idle-timeout\s+[1-9]/i.test(cfg) ? ok : fail('No idle-timeout configured');
      if (vendor === 'fortinet') return /admintimeout\s+[1-9]/i.test(cfg) ? ok : fail('No admintimeout configured');
      if (vendor === 'vyos') return /client-timeout\s+[1-9]/i.test(cfg) ? ok : fail('No client-timeout configured');
      return keyFallback();
    }

    case 'CIS-1.7': {
      const m =
        cfg.match(/snmp-server\s+community\s+(public|private)\b/i) ||
        cfg.match(/snmp-agent\s+community\s+(read|write)\s+(cipher\s+)?(public|private)\b/i) ||
        cfg.match(/(^|\s)community\s+"?(public|private)"?(\s|$)/im) ||
        cfg.match(/community\s*=\s*(public|private)\b/i) ||
        cfg.match(/communities\s+\{?\s*(public|private)\b/i);
      if (vendor === 'mikrotik' && m && /disabled\s*=\s*yes/i.test(cfg)) return ok;
      if (vendor === 'paloalto' && /version\s+v2c/i.test(cfg) && /community-string\s+(public|private)\b/i.test(cfg)) return fail('v2c with default community');
      return m ? fail(`Default community string "${m[0].match(/public|private/i)?.[0]}" in use`) : ok;
    }

    case 'CIS-1.10': {
      if (vendor === 'cisco_ios' && vtyBlocks.length > 0) {
        const bad = vtyBlocks.filter((b) => !blockFind(b, /^access-class\s+\S+\s+in\b/i));
        return bad.length ? fail(bad.map((b) => `${b.text}: no inbound access-class`).join('; ')) : ok;
      }
      return keyFallback();
    }

    case 'CIS-1.8':
    case 'CIS-1.9':
    case 'CIS-1.11':
      return keyFallback();

    case 'CIS-1.12': {
      const hasNtp = /\bntp\b|ntp-service|ntpserver/i.test(cfg);
      if (!hasNtp) return ok; // CIS-1.11 already covers "no NTP at all"
      return keyFallback();
    }

    case 'CIS-1.13': {
      if (vendor === 'mikrotik') {
        return /\/snmp\s+community[\s\S]*?(add|set)\b(?![^\n]*disabled=yes)/i.test(cfg) && /\/snmp[\s\S]*enabled=yes/i.test(cfg)
          ? fail('SNMP enabled with v1/v2c communities')
          : ok;
      }
      if (vendor === 'paloalto') return /version\s+v2c/i.test(cfg) ? fail('SNMP version v2c') : ok;
      const m = cfg.match(/^\s*(snmp-server\s+community|snmp-agent\s+community|set\s+snmp\s+community|snmp\s*\{[^}]*community|config\s+system\s+snmp\s+community)[^\n]*/im)
        || (vendor === 'vyos' || vendor === 'juniper' ? cfg.match(/^\s*(set\s+)?(service\s+)?snmp\s+community[^\n]*/im) : null);
      return m ? fail(sanitizeConfig(m[0].trim())) : ok;
    }

    case 'CIS-1.14': {
      const found = cfg.match(/^\s*(service\s+(ipv4\s+)?(tcp|udp)-small-servers|ip\s+finger|service\s+finger|service\s+pad)\b.*$/gim);
      return found ? fail(found.map((l) => l.trim()).join('; ')) : ok;
    }

    case 'CIS-1.15': {
      const weak =
        vendor === 'arista'
          ? cfg.match(/^\s*username\s+\S+.*\b(secret\s+0\s|nopassword)\b.*$/gim)
          : cfg.match(/^\s*(enable\s+password\b.*|enable\s+secret\s+5\s.*|username\s+\S+.*\bpassword\s+(0\s|7\s|(?!\d\s)\S+).*|username\s+\S+.*\bsecret\s+5\s.*)$/gim);
      return weak ? fail(weak.map((l) => sanitizeConfig(l.trim())).join('; ')) : ok;
    }

    case 'CIS-1.16':
      return keyFallback();

    case 'CIS-1.17': {
      if (vendor === 'cisco_ios') {
        const cp = findBlocks(tree, /^control-plane\b/i);
        return cp.some((b) => blockHas(b, /^service-policy\s+input\b/i)) ? ok : fail('No control-plane service-policy input');
      }
      if (vendor === 'cisco_nxos') return /copp\s+profile\s+none/i.test(cfg) ? fail('copp profile none') : ok;
      if (vendor === 'juniper') {
        return /lo0\s+unit\s+0\s+family\s+inet\s+filter\s+input/i.test(cfg) || /lo0[\s\S]{0,200}filter\s*\{?\s*input/i.test(cfg)
          ? ok
          : fail('No input filter on lo0');
      }
      return keyFallback();
    }

    case 'CIS-1.18': {
      const unused = findUnusedEnabledInterfaces(tree);
      if (unused.length === 0) return ok;
      const shown = unused.slice(0, 8).join(', ');
      return fail(`${unused.length} enabled interface(s) with no configuration: ${shown}${unused.length > 8 ? ', …' : ''}`);
    }

    case 'CIS-1.19':
      return keyFallback();

    default:
      return ok;
  }
}

/**
 * Deterministic multi-vendor rule evaluation. Pass the RAW (unredacted)
 * config: several rules (SNMP communities, password types) look at values
 * the redactor removes. Evidence strings are redacted before being returned.
 */
export function evaluateConfigDeterministically(
  rawConfig: string,
  vendorInput: string
): { riskLevel: SeverityLevel; findings: ValidatedFinding[]; rulesEvaluated: number } {
  const vendor = detectVendor(vendorInput);
  const findings: ValidatedFinding[] = [];
  const cleanConfig = sanitizeConfigForScanning(rawConfig);

  if (!cleanConfig.trim()) {
    return { riskLevel: 'LOW', findings: [], rulesEvaluated: 0 };
  }

  // Indentation matters for block-scoped rules, so evaluate the original
  // text (comment lines dropped) rather than a flattened version.
  const cfg = stripCommentLines(rawConfig);
  const tree = parseIndentedConfig(cfg);
  const ctx: EvalContext = { cfg, tree, vtyBlocks: findBlocks(tree, /^line\s+vty\b/i) };

  let rulesEvaluated = 0;
  for (const rule of CIS_BENCHMARK_MATRIX) {
    if (rule.appliesTo && !rule.appliesTo.includes(vendor)) continue;
    const vConfig = rule.vendors[vendor] || rule.vendors.generic;
    if (!vConfig) continue;
    rulesEvaluated++;

    const outcome = evaluateRule(rule, vendor, ctx, vConfig);
    if (outcome.violated) {
      findings.push({
        ruleId: rule.ruleId,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        remediationCli: vConfig.remediationCli || 'Apply vendor-recommended CIS baseline configuration.',
        cisControl: rule.cisControl,
        frameworks: RULE_FRAMEWORKS[rule.ruleId],
        evidence: outcome.evidence ? sanitizeConfig(outcome.evidence) : undefined,
      });
    }
  }

  let riskLevel: SeverityLevel = 'LOW';
  if (findings.some((f) => f.severity === 'CRITICAL')) riskLevel = 'CRITICAL';
  else if (findings.some((f) => f.severity === 'HIGH')) riskLevel = 'HIGH';
  else if (findings.some((f) => f.severity === 'MEDIUM')) riskLevel = 'MEDIUM';

  return { riskLevel, findings, rulesEvaluated };
}

function stripCommentLines(rawConfig: string): string {
  return (rawConfig || '')
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return t.length > 0 && !t.startsWith('!') && !t.startsWith(';') && !t.startsWith('//') && !t.startsWith('#');
    })
    .join('\n');
}

/** Rule ids the engine evaluates for a platform. */
export function applicableRuleIds(vendorInput: string): string[] {
  const vendor = detectVendor(vendorInput);
  return CIS_BENCHMARK_MATRIX.filter((r) => (!r.appliesTo || r.appliesTo.includes(vendor)) && (r.vendors[vendor] || r.vendors.generic)).map((r) => r.ruleId);
}

/** Resolves a stored finding (rule_id, or title for rows saved before rule_id existed). */
export function resolveRuleId(ruleId: string | null | undefined, title: string | null | undefined): string | null {
  if (ruleId && CIS_BENCHMARK_MATRIX.some((r) => r.ruleId === ruleId)) return ruleId;
  return CIS_BENCHMARK_MATRIX.find((r) => r.title === title)?.ruleId ?? null;
}
