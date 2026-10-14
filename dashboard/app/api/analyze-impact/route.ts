// dashboard/app/api/analyze-impact/route.ts
// Change-impact simulation for a proposed CLI change. A deterministic
// keyword floor guarantees that commands which can reboot a device or cut
// management access are never shown as LOW, whatever the AI says.
import { NextRequest, NextResponse } from 'next/server';
import { scanForPromptInjection, wrapUntrustedContent } from '@/lib/security';
import { sanitizeConfig } from '@/lib/sanitizer';
import { requireUser, requireDevice } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { enforceRateLimit } from '@/lib/rateLimit';
import { ImpactBody } from '@/lib/validation';
import { readJson, routeError } from '@/lib/http';
import { groqJson } from '@/lib/groq';
import { generateSmartRollback } from '@/lib/rollback';
import { getHighestRiskLevel, normalizeRiskLevel, riskBadge, type RiskLevel } from '@/lib/risk';

function getDeterministicImpactFloor(cliCommand: string): RiskLevel {
  let floor: RiskLevel = 'LOW';
  for (const line of cliCommand.split('\n').map((l) => l.trim().toLowerCase()).filter(Boolean)) {
    // Reboots and wipes: service down or config lost.
    if (/\b(reload|reboot|erase|zeroize|factory[- ]?reset)\b/.test(line) || /^format\b/.test(line) || /^delete\s+(\/force\s+)?(flash|bootflash|nvram|startup|disk)/.test(line)) {
      return 'CRITICAL';
    }
    // Can lock you out of the device or drop a link.
    if (
      /^no\s+(aaa\s+new-model|ip\s+ssh|ssh\b|username\b|enable\b)/.test(line) ||
      /^transport\s+input\s+(none|telnet)/.test(line) ||
      /^no\s+transport\s+input/.test(line) ||
      /^shutdown$/.test(line) ||
      /\baccess-class\b/.test(line)
    ) {
      floor = getHighestRiskLevel(floor, 'HIGH');
      continue;
    }
    // Routing / ACL / addressing / VLAN changes can interrupt traffic.
    if (/^(no\s+)?(ip\s+route|ip\s+address|ip\s+access-list|access-list|vlan\b|spanning-tree|router\s+\w+|snmp-server|ntp\b)/.test(line) || /default-gateway/.test(line)) {
      floor = getHighestRiskLevel(floor, 'MEDIUM');
    }
  }
  return floor;
}

function buildMarkdown(vendor: string, impact: RiskLevel, disruption: RiskLevel, narrative: string, rollback: string[]): string {
  return `### 📊 CLI Command Impact Assessment

* **Target OS Platform:** \`${vendor}\`
* **Evaluated Impact Level:** **${riskBadge(impact)}**
* **Disruption Risk:** **${riskBadge(disruption)}**

---

### 🔍 Operational Impact Breakdown
> ${narrative}

---

### 🔄 Rollback Script
*Review before use. Execute to revert the change if service is disrupted:*

\`\`\`cli
${rollback.length ? rollback.join('\n') : '! Manual configuration verification required.'}
\`\`\``;
}

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'operator');
    const body = ImpactBody.parse(await readJson(req));
    enforceRateLimit(ctx.userId, 'ai-impact', 30);

    let vendor = body.vendor || 'Generic Network OS';
    let activeConfig = body.activeConfig || '';
    let orgId: string | null = null;
    if (body.deviceId) {
      const device = await requireDevice(ctx, body.deviceId, 'operator');
      vendor = body.vendor || device.netmiko_type || device.vendor || vendor;
      activeConfig = activeConfig || device.last_config || '';
      orgId = device.org_id;
    }

    const cliCommand = body.proposedCommand.trim();
    // Detectors, not gates (see lib/security.ts).
    const commandScan = scanForPromptInjection(cliCommand);
    const configScan = activeConfig ? scanForPromptInjection(activeConfig) : { flagged: false };
    const configContext = activeConfig.trim()
      ? wrapUntrustedContent('active_device_configuration', sanitizeConfig(activeConfig).slice(0, 4000))
      : 'No active device configuration supplied. Analyze command impact using syntax and vendor defaults.';

    const ai = await groqJson<{ impactLevel?: string; disruptionRisk?: string; analysis?: string; rollbackCommands?: unknown }>({
      label: 'impact',
      system: `You are a network infrastructure safety auditor. Analyze proposed CLI commands against the target running configuration for ${vendor}.
Return JSON ONLY with keys: impactLevel (CRITICAL|HIGH|MEDIUM|LOW), disruptionRisk (CRITICAL|HIGH|MEDIUM|LOW), analysis (markdown explaining operational impact, risks and syntax validity), rollbackCommands (array of CLI commands that revert the change line by line).
Rollback rules: invert 'no <cmd>' to '<cmd>' and '<cmd>' to 'no <cmd>'; invert 'shutdown' to 'no shutdown'; keep context headers such as 'interface Ethernet1/1' or 'line vty 0 15'.`,
      user: `Vendor OS: ${vendor}\n\nRunning Configuration Context:\n${configContext}\n\nProposed CLI Command:\n${sanitizeConfig(cliCommand)}`,
      temperature: 0.1,
    });

    const floor = getDeterministicImpactFloor(cliCommand);
    const keywordDestructive = floor === 'CRITICAL' || floor === 'HIGH';
    const impactLevel = getHighestRiskLevel(floor, ai ? normalizeRiskLevel(ai.data.impactLevel, 'MEDIUM') : keywordDestructive ? 'HIGH' : 'LOW');
    const disruptionRisk = getHighestRiskLevel(floor, ai ? normalizeRiskLevel(ai.data.disruptionRisk, 'MEDIUM') : keywordDestructive ? 'CRITICAL' : 'LOW');
    const aiRollback = Array.isArray(ai?.data.rollbackCommands) ? (ai!.data.rollbackCommands as unknown[]).map(String).filter(Boolean) : [];
    const rollbackCommands = aiRollback.length ? aiRollback : generateSmartRollback(cliCommand, vendor);
    const narrative =
      ai?.data.analysis ||
      (keywordDestructive
        ? '⚠️ **AI service unavailable — keyword check only.** This command can interrupt service or cut management access.'
        : '⚠️ **AI service unavailable — keyword check only.** No disruptive keyword was found, but no AI review was done. Review manually before applying.');

    const analysis = buildMarkdown(vendor, impactLevel, disruptionRisk, narrative, rollbackCommands);
    await audit(ctx, { action: 'simulate.impact', orgId, targetType: 'device', targetId: body.deviceId ?? null, details: { impactLevel, lines: cliCommand.split('\n').length } });

    return NextResponse.json({
      success: true,
      proposedCommand: cliCommand,
      impactLevel,
      disruptionRisk,
      analysis,
      output: analysis,
      rollbackCommands,
      aiUnavailable: !ai,
      deterministicFloor: floor,
      promptInjectionFlagged: commandScan.flagged || configScan.flagged,
      promptInjectionSource: commandScan.flagged && configScan.flagged ? 'command_and_config' : commandScan.flagged ? 'command' : configScan.flagged ? 'config' : null,
    });
  } catch (err) {
    return routeError(err, 'POST /api/analyze-impact');
  }
}
