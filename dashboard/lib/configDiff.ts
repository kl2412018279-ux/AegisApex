// dashboard/lib/configDiff.ts
// Configuration change tracking: what changed between two snapshots, which
// of those changes weaken security, and which CIS rules started (or
// stopped) failing because of them.
import { diffLines } from 'diff';
import { evaluateConfigDeterministically } from './cisBenchmarks';
import { sanitizeConfig } from './sanitizer';
import { getHighestRiskLevel, type RiskLevel } from './risk';

export interface DiffLine {
  type: 'add' | 'del' | 'same';
  text: string;
}

export interface RiskyChange {
  severity: RiskLevel;
  title: string;
  line: string;
  change: 'added' | 'removed';
}

export interface DriftReport {
  addedLines: number;
  removedLines: number;
  lines: DiffLine[];
  riskyChanges: RiskyChange[];
  newFindings: string[];
  resolvedFindings: string[];
  severity: RiskLevel | null;
}

// Lines that change on every collection without anyone touching the device.
const NOISE = [
  /^!\s*(last configuration change|nvram config last updated|no configuration change since)/i,
  /^!?\s*time:/i,
  /^building configuration/i,
  /^current configuration\s*:/i,
  /^ntp clock-period/i,
  /^#\s*(last commit|generated)/i,
  /^##\s*last (changed|commit)/i,
  /^\s*$/,
];

function normalize(config: string): string {
  return (config || '')
    .split(/\r?\n/)
    .map((l) => l.replace(/\s+$/, ''))
    .filter((l) => !NOISE.some((re) => re.test(l.trim())))
    .join('\n');
}

interface Rule {
  re: RegExp;
  severity: RiskLevel;
  title: string;
}

const RISKY_ADDITIONS: Rule[] = [
  { re: /^(transport\s+input\s+(telnet|all|.*telnet)|feature\s+telnet|telnet\s+server\s+enable|set\s+system\s+services\s+telnet|set\s+service\s+telnet)/i, severity: 'CRITICAL', title: 'Telnet management enabled' },
  { re: /^no\s+aaa\s+new-model/i, severity: 'CRITICAL', title: 'AAA disabled' },
  { re: /^(permit\s+(ip\s+)?any(\s+any)?\b|\d+\s+permit\s+(ip\s+)?any\s+any|access-list\s+\S+\s+permit\s+(ip\s+)?any\s+any)/i, severity: 'HIGH', title: 'Permissive "permit any" ACL entry added' },
  { re: /^snmp-server\s+community\s+\S+\s+rw\b/i, severity: 'CRITICAL', title: 'SNMP read-write community added' },
  { re: /^(snmp-server\s+community|snmp-agent\s+community|set\s+snmp\s+community)/i, severity: 'HIGH', title: 'SNMPv1/v2c community added' },
  { re: /^username\s+\S+.*privilege\s+15/i, severity: 'HIGH', title: 'New or changed privileged local account' },
  { re: /^no\s+service\s+password-encryption/i, severity: 'HIGH', title: 'Password encryption disabled' },
  { re: /^set\s+allowaccess\b.*\b(telnet|http)\b/i, severity: 'HIGH', title: 'Insecure management protocol allowed on interface' },
  { re: /^ip\s+http\s+server\b/i, severity: 'MEDIUM', title: 'HTTP management server enabled' },
  { re: /^exec-timeout\s+0(\s+0)?$/i, severity: 'MEDIUM', title: 'Session timeout disabled' },
  { re: /^(ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0|ip\s+route\s+vrf\s+\S+\s+0\.0\.0\.0|set\s+routing-options\s+static\s+route\s+0\.0\.0\.0\/0)/i, severity: 'MEDIUM', title: 'Default route changed' },
  { re: /^(crypto\s+isakmp\s+key|pre-shared-key|set\s+psksecret)/i, severity: 'MEDIUM', title: 'VPN pre-shared key changed' },
  { re: /^(no\s+logging\s+(host\s+)?\S+|no\s+logging\s+on)/i, severity: 'MEDIUM', title: 'Logging destination removed' },
];

const RISKY_REMOVALS: Rule[] = [
  { re: /^access-class\s+\S+\s+in/i, severity: 'HIGH', title: 'Management access ACL removed' },
  { re: /^aaa\s+(new-model|authentication\s+login)/i, severity: 'HIGH', title: 'AAA authentication removed' },
  { re: /^service\s+password-encryption/i, severity: 'HIGH', title: 'Password encryption removed' },
  { re: /^transport\s+input\s+ssh$/i, severity: 'MEDIUM', title: 'SSH-only transport removed' },
  { re: /^(logging\s+(host\s+)?\d|logging\s+server|set\s+system\s+syslog\s+host|info-center\s+loghost)/i, severity: 'MEDIUM', title: 'Central logging destination removed' },
  { re: /^ntp\s+authenticate/i, severity: 'MEDIUM', title: 'NTP authentication removed' },
  { re: /^ip\s+access-group\s+\S+\s+in/i, severity: 'MEDIUM', title: 'Interface inbound ACL removed' },
  { re: /^service-policy\s+input/i, severity: 'MEDIUM', title: 'Control-plane / input policy removed' },
  { re: /^shutdown$/i, severity: 'LOW', title: 'Interface brought up (shutdown removed)' },
];

export function classifyRiskyChanges(added: string[], removed: string[]): RiskyChange[] {
  const out: RiskyChange[] = [];
  const match = (lines: string[], rules: Rule[], change: RiskyChange['change']) => {
    for (const raw of lines) {
      const line = raw.trim();
      const rule = rules.find((r) => r.re.test(line));
      if (rule) out.push({ severity: rule.severity, title: rule.title, line: sanitizeConfig(line), change });
    }
  };
  match(added, RISKY_ADDITIONS, 'added');
  match(removed, RISKY_REMOVALS, 'removed');
  return out;
}

export function computeDrift(previous: string, current: string, vendor: string): DriftReport {
  const parts = diffLines(normalize(previous), normalize(current));
  const lines: DiffLine[] = [];
  const added: string[] = [];
  const removed: string[] = [];

  for (const part of parts) {
    const partLines = part.value.replace(/\n$/, '').split('\n');
    const type: DiffLine['type'] = part.added ? 'add' : part.removed ? 'del' : 'same';
    for (const text of partLines) {
      lines.push({ type, text: sanitizeConfig(text) });
      if (type === 'add') added.push(text);
      if (type === 'del') removed.push(text);
    }
  }

  const riskyChanges = classifyRiskyChanges(added, removed);

  const before = new Set(evaluateConfigDeterministically(previous, vendor).findings.map((f) => f.ruleId));
  const after = evaluateConfigDeterministically(current, vendor).findings;
  const afterIds = new Set(after.map((f) => f.ruleId));
  const newFindings = after.filter((f) => !before.has(f.ruleId)).map((f) => `${f.ruleId} ${f.title}`);
  const resolvedFindings = Array.from(before).filter((id) => !afterIds.has(id));

  const severities: RiskLevel[] = riskyChanges.map((c) => c.severity);
  for (const f of after.filter((x) => !before.has(x.ruleId))) severities.push(f.severity);

  return {
    addedLines: added.length,
    removedLines: removed.length,
    lines,
    riskyChanges,
    newFindings,
    resolvedFindings,
    severity: severities.length ? getHighestRiskLevel(...severities) : null,
  };
}

/** Collapses unchanged runs so the UI shows changes with a little context. */
export function withContext(lines: DiffLine[], context = 3): Array<DiffLine | { type: 'gap'; count: number }> {
  const keep = new Array(lines.length).fill(false);
  lines.forEach((l, i) => {
    if (l.type !== 'same') for (let j = Math.max(0, i - context); j <= Math.min(lines.length - 1, i + context); j++) keep[j] = true;
  });
  const out: Array<DiffLine | { type: 'gap'; count: number }> = [];
  let gap = 0;
  lines.forEach((l, i) => {
    if (keep[i]) {
      if (gap) out.push({ type: 'gap', count: gap });
      gap = 0;
      out.push(l);
    } else gap++;
  });
  if (gap) out.push({ type: 'gap', count: gap });
  return out;
}
