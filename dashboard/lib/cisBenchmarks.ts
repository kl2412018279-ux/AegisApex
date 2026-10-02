//C:\Users\hp\aiops-securewatch\dashboard\lib\cisBenchmarks.ts
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

export interface CISBenchmarkRule {
  ruleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  cisControl: string;
  vendors: Record<VendorType, VendorRuleConfig>;
}

export interface ValidatedFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  remediationCli: string;
  cisControl?: string;
}

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
    cisControl: 'CIS Control 3.3: Data Protection',
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
    cisControl: 'CIS Control 3.4: Access Control Management',
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
    cisControl: 'CIS Control 3.1: Secure Network Infrastructure',
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
    cisControl: 'CIS Control 3.1: Secure Network Infrastructure',
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
    cisControl: 'CIS Control 3.1: Secure Network Infrastructure',
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
    cisControl: 'CIS Control 3.3: Account Management',
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
];

/**
 * Deterministic multi-vendor rule evaluation engine with comment-sanitized parsing.
 */
export function evaluateConfigDeterministically(
  rawConfig: string,
  vendorInput: string
): { riskLevel: SeverityLevel; findings: ValidatedFinding[] } {
  const vendor = detectVendor(vendorInput);
  const findings: ValidatedFinding[] = [];
  const cleanConfig = sanitizeConfigForScanning(rawConfig);

  if (!cleanConfig.trim()) {
    return { riskLevel: 'LOW', findings: [] };
  }

  for (const rule of CIS_BENCHMARK_MATRIX) {
    const vConfig = rule.vendors[vendor] || rule.vendors['generic'];
    let isViolated = false;

    switch (rule.ruleId) {
      case 'CIS-1.1': // Password Encryption
        if (vendor.startsWith('cisco') || vendor === 'arista' || vendor === 'dell_os10') {
          if (/no\s+service\s+password-encryption/i.test(cleanConfig) || !/service\s+password-encryption/i.test(cleanConfig)) {
            isViolated = true;
          }
        } else if (vendor === 'juniper') {
          if (!/encrypted-password|\$9\$/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'vyos') {
          if (/plaintext-password/i.test(cleanConfig) || !/encrypted-password/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'extreme_exos') {
          if (!/configure\s+account.*encrypted/i.test(cleanConfig) && /configure\s+account.*password/i.test(cleanConfig)) {
            isViolated = true;
          }
        } else {
          isViolated = !vConfig.detectionKeys.some((k) => new RegExp(k, 'i').test(cleanConfig));
        }
        break;

      case 'CIS-1.2': // AAA Authentication
        if (vendor.startsWith('cisco')) {
          isViolated = !/aaa\s+(new-model|group|authentication)/i.test(cleanConfig);
        } else if (vendor === 'arista' || vendor === 'dell_os10' || vendor === 'aruba_hpe') {
          isViolated = !/aaa\s+authentication\s+login/i.test(cleanConfig);
        } else if (vendor === 'juniper') {
          isViolated = !/(authentication-order|system\s+login|tacplus|radius)/i.test(cleanConfig);
        } else if (vendor === 'fortinet') {
          isViolated = !/config\s+user\s+(radius|tacacs|group)/i.test(cleanConfig);
        } else if (vendor === 'paloalto') {
          isViolated = !/authentication-profile/i.test(cleanConfig);
        } else if (vendor === 'huawei') {
          isViolated = !/\baaa\b/i.test(cleanConfig);
        } else if (vendor === 'f5_tmsh') {
          isViolated = !/auth\s+source/i.test(cleanConfig);
        } else if (vendor === 'nokia_sros') {
          isViolated = !/security\s+aaa/i.test(cleanConfig);
        } else if (vendor === 'vyos') {
          isViolated = !/(radius-server|tacacs-server)/i.test(cleanConfig);
        } else if (vendor === 'extreme_exos') {
          isViolated = !/enable\s+aaa/i.test(cleanConfig);
        } else if (vendor === 'mikrotik') {
          isViolated = !/use-radius\s*=\s*yes/i.test(cleanConfig);
        } else {
          isViolated = !vConfig.detectionKeys.some((k) => new RegExp(k, 'i').test(cleanConfig));
        }
        break;

      case 'CIS-1.3': // Remote Transport SSH Only
        if (vendor.startsWith('cisco') || vendor === 'arista' || vendor === 'dell_os10') {
          const hasSshOnly = /transport\s+input\s+ssh\b/i.test(cleanConfig);
          const hasTelnet = /transport\s+input\s+.*telnet/i.test(cleanConfig);
          const hasAll = /transport\s+input\s+(all|telnet\s+ssh|ssh\s+telnet)/i.test(cleanConfig);
          if (hasTelnet || hasAll || !hasSshOnly) isViolated = true;
        } else if (vendor === 'juniper') {
          const hasSsh = /system\s+services\s+ssh/i.test(cleanConfig);
          const hasTelnet = /system\s+services\s+telnet/i.test(cleanConfig);
          if (!hasSsh || hasTelnet) isViolated = true;
        } else if (vendor === 'fortinet') {
          if (/allowaccess.*telnet/i.test(cleanConfig) && !/unset\s+allowaccess.*telnet/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'paloalto') {
          if (!/disable-telnet\s+yes/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'huawei') {
          if (/telnet\s+server\s+enable/i.test(cleanConfig) || !/protocol\s+inbound\s+ssh/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'aruba_hpe') {
          if (!/no\s+telnet-server/i.test(cleanConfig) && /telnet-server/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'vyos') {
          if (/service\s+telnet/i.test(cleanConfig) || !/service\s+ssh/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'extreme_exos') {
          if (/\benable\s+telnet\b/i.test(cleanConfig) || !/\bdisable\s+telnet\b/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'mikrotik') {
          if (/\/ip\s+service.*telnet/i.test(cleanConfig) && !/disable\s+telnet/i.test(cleanConfig)) isViolated = true;
        } else {
          if (/telnet/i.test(cleanConfig) && !/no\s+telnet|disable\s+telnet/i.test(cleanConfig)) isViolated = true;
        }
        break;

      case 'CIS-1.4': // HTTP Management Disabled
        if (vendor.startsWith('cisco') || vendor === 'dell_os10') {
          if (/ip\s+http\s+server\b/i.test(cleanConfig) && !/no\s+ip\s+http\s+server/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'arista') {
          if (/protocol\s+http\b/i.test(cleanConfig) && !/no\s+protocol\s+http/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'juniper') {
          if (/web-management\s+http\b/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'fortinet') {
          if (/allowaccess.*http\b/i.test(cleanConfig) && !/unset\s+allowaccess.*http/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'paloalto') {
          if (!/disable-http\s+yes/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'huawei') {
          if (/http\s+server\s+enable/i.test(cleanConfig) && !/undo\s+http\s+server\s+enable/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'aruba_hpe') {
          if (/web-management\s+http/i.test(cleanConfig) && !/no\s+web-management\s+http/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'extreme_exos') {
          if (/\benable\s+web\b/i.test(cleanConfig) && !/\bdisable\s+web\b/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'mikrotik') {
          if (/\/ip\s+service.*www\b/i.test(cleanConfig) && !/disable\s+www/i.test(cleanConfig)) isViolated = true;
        } else {
          if (/\bhttp\s+server\b/i.test(cleanConfig) && !/no\s+http|disable\s+http|undo\s+http/i.test(cleanConfig)) isViolated = true;
        }
        break;

      case 'CIS-1.5': // SSH Version 2
        if (vendor.startsWith('cisco') || vendor === 'arista' || vendor === 'dell_os10' || vendor === 'aruba_hpe') {
          isViolated = !/(ip\s+ssh\s+version\s+2|ssh\s+version\s+2|ssh\s+server\s+v2)/i.test(cleanConfig);
        } else if (vendor === 'juniper' || vendor === 'vyos') {
          isViolated = !/protocol-version\s+v2/i.test(cleanConfig);
        } else if (vendor === 'huawei' || vendor === 'extreme_exos') {
          isViolated = !/ssh\s+(server\s+)?version\s+v?2/i.test(cleanConfig);
        } else if (vendor === 'fortinet') {
          isViolated = /ssh-v1\s+enable/i.test(cleanConfig);
        } else if (vendor === 'paloalto') {
          isViolated = /ssh-v1\s+yes/i.test(cleanConfig);
        } else {
          isViolated = !/version\s+2|v2/i.test(cleanConfig);
        }
        break;

      case 'CIS-1.6': // EXEC Session Timeout
        if (/exec-timeout\s+0\s+0|admintimeout\s+0|idle-timeout\s+0|client-timeout\s+0/i.test(cleanConfig)) {
          isViolated = true;
        } else if (vendor.startsWith('cisco') || vendor === 'arista' || vendor === 'dell_os10') {
          if (!/exec-timeout\s+[1-9]/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'juniper' || vendor === 'paloalto' || vendor === 'huawei' || vendor === 'aruba_hpe' || vendor === 'extreme_exos') {
          if (!/idle-timeout\s+[1-9]/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'fortinet') {
          if (!/admintimeout\s+[1-9]/i.test(cleanConfig)) isViolated = true;
        } else if (vendor === 'vyos') {
          if (!/client-timeout\s+[1-9]/i.test(cleanConfig)) isViolated = true;
        }
        break;

      default:
        break;
    }

    if (isViolated) {
      findings.push({
        ruleId: rule.ruleId,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        remediationCli: vConfig.remediationCli || 'Apply vendor-recommended CIS baseline configuration.',
        cisControl: rule.cisControl,
      });
    }
  }

  let riskLevel: SeverityLevel = 'LOW';
  if (findings.some((f) => f.severity === 'CRITICAL')) {
    riskLevel = 'CRITICAL';
  } else if (findings.some((f) => f.severity === 'HIGH')) {
    riskLevel = 'HIGH';
  } else if (findings.some((f) => f.severity === 'MEDIUM')) {
    riskLevel = 'MEDIUM';
  }

  return {
    riskLevel,
    findings,
  };
}