//C:\Users\hp\aiops-securewatch\dashboard\app\api\analyze-impact\route.ts
import { NextRequest, NextResponse } from 'next/server';
import { scanForPromptInjection, wrapUntrustedContent, PromptInjectionScanResult } from '@/lib/security';

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL ||  'openai/gpt-oss-120b';

export type ImpactLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type DisruptionRisk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface ImpactAnalysisResult {
  impactLevel: ImpactLevel;
  disruptionRisk: DisruptionRisk;
  analysis: string;
  rollbackCommands: string[];
}

function normalizeImpactLevel(val?: string): ImpactLevel {
  const normalized = String(val || '').toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized)) {
    return normalized as ImpactLevel;
  }
  return 'MEDIUM';
}

function normalizeDisruptionRisk(val?: string): DisruptionRisk {
  const normalized = String(val || '').toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized)) {
    return normalized as DisruptionRisk;
  }
  return 'MEDIUM';
}

/**
 * Line-by-line CLI syntax reversal engine for fallback execution.
 */
function generateSmartRollback(cliCommand: string, vendor: string = 'generic'): string[] {
  const lines = cliCommand.split('\n').map((l) => l.trim()).filter(Boolean);
  const rollbackLines: string[] = [];

  for (const line of lines) {
    const lower = line.toLowerCase();

    // 1. Destructive / Irreversible Operations
    if (
      lower.includes('reload') ||
      lower.includes('reboot') ||
      lower.includes('erase') ||
      lower.includes('write erase')
    ) {
      rollbackLines.push(`! Reversal not possible via CLI for destructive operation: "${line}"`);
      continue;
    }

    // 2. Context Headers (Interfaces, Line VTY, Router, VLAN)
    if (
      lower.startsWith('interface ') ||
      lower.startsWith('line ') ||
      lower.startsWith('router ') ||
      lower.startsWith('vlan ') ||
      lower.startsWith('policy-map ')
    ) {
      rollbackLines.push(line);
      continue;
    }

    // 3. Invert "no <command>" -> "<command>"
    if (lower.startsWith('no ')) {
      const inverted = line.substring(3).trim();
      rollbackLines.push(inverted);
      continue;
    }

    // 4. Invert "shutdown" -> "no shutdown"
    if (lower === 'shutdown') {
      rollbackLines.push('no shutdown');
      continue;
    }

    // 5. Invert "<command>" -> "no <command>"
    rollbackLines.push(`no ${line}`);
  }

  return rollbackLines.length > 0
    ? rollbackLines
    : ['! Manual configuration inspection required for rollback.'];
}

/**
 * Standardizes output markdown layout for UI rendering.
 */
function buildFormattedMarkdown(
  vendor: string,
  impactLevel: ImpactLevel,
  disruptionRisk: DisruptionRisk,
  analysisNarrative: string,
  rollbackCommands: string[]
): string {
  const impactBadge =
    impactLevel === 'CRITICAL'
      ? '🔴 CRITICAL'
      : impactLevel === 'HIGH'
      ? '🟠 HIGH'
      : impactLevel === 'MEDIUM'
      ? '🟡 MEDIUM'
      : '🟢 LOW';

  const riskBadge =
    disruptionRisk === 'CRITICAL'
      ? '🔴 CRITICAL'
      : disruptionRisk === 'HIGH'
      ? '🟠 HIGH'
      : disruptionRisk === 'MEDIUM'
      ? '🟡 MEDIUM'
      : '🟢 LOW';

  const rollbackBlock = rollbackCommands.length > 0
    ? rollbackCommands.join('\n')
    : '! Manual configuration verification required.';

  return `### 📊 CLI Command Impact Assessment

* **Target OS Platform:** \`${vendor || 'Generic Network OS'}\`
* **Evaluated Impact Level:** **${impactBadge}**
* **Disruption Risk:** **${riskBadge}**

---

### 🔍 Operational Impact Breakdown
> ${analysisNarrative}

---

### 🔄 Disaster Recovery Rollback Script
*Execute these CLI commands to revert changes if service is disrupted:*

\`\`\`cli
${rollbackBlock}
\`\`\``;
}

function fallbackImpactAnalysis(cliCommand: string, vendor?: string): ImpactAnalysisResult {
  const cmdLower = cliCommand.toLowerCase().trim();
  const isDestructive =
    cmdLower.includes('reload') ||
    cmdLower.includes('reboot') ||
    cmdLower.includes('shutdown') ||
    cmdLower.includes('delete') ||
    cmdLower.includes('erase');

  const rollbackCommands = generateSmartRollback(cliCommand, vendor);

  const narrative = isDestructive
    ? '⚠️ **High Risk Operation Detected.** Executing this command will cause immediate service interruption or interface down states on active connections.'
    : '✅ **Standard Operations Command.** Low probability of core network disruption. Verify service availability after apply.';

  const formattedAnalysis = buildFormattedMarkdown(
    vendor || 'Generic Device',
    isDestructive ? 'HIGH' : 'LOW',
    isDestructive ? 'CRITICAL' : 'LOW',
    narrative,
    rollbackCommands
  );

  return {
    impactLevel: isDestructive ? 'HIGH' : 'LOW',
    disruptionRisk: isDestructive ? 'CRITICAL' : 'LOW',
    analysis: formattedAnalysis,
    rollbackCommands,
  };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const { proposedCommand, proposed_cli, vendor, activeConfig } = body;

    const cliCommand = (proposedCommand || proposed_cli || '').trim();

    if (!cliCommand) {
      return NextResponse.json(
        { success: false, error: 'A CLI command (proposedCommand or proposed_cli) is required.' },
        { status: 400 }
      );
    }

    // FIX: both gates below used to return 422 and refuse the whole request.
    // For the pasted-in device config (configScan) that's the same problem
    // as in api/scan/route.ts: it's attacker-influenceable data, so blocking
    // on a match lets an attacker silently make this endpoint useless for a
    // tampered device. For the operator-typed command (commandScan) a false
    // positive (e.g. a command that legitimately contains the word "system:")
    // would otherwise block a real operator action with no way around it.
    // Both are now flags surfaced in the response, not hard stops. The
    // config text is wrapped in an explicit untrusted-data boundary before
    // it reaches the LLM prompt, which is the actual mitigation.
    const commandScan = scanForPromptInjection(cliCommand);

    let configContext = 'No active device configuration supplied. Analyze command impact using syntax and vendor defaults.';
    let configScan: PromptInjectionScanResult = { flagged: false };
    if (typeof activeConfig === 'string' && activeConfig.trim() !== '') {
      configScan = scanForPromptInjection(activeConfig);
      configContext = wrapUntrustedContent('active_device_configuration', activeConfig.slice(0, 4000));
    }

    let parsedResult: Partial<ImpactAnalysisResult> | null = null;
    const vendorName = vendor || 'Generic Network OS';

    if (GROQ_API_KEY) {
      try {
        const systemPrompt = `You are a network infrastructure safety auditor. Analyze proposed CLI commands against target running configurations for ${vendorName}.
Return JSON ONLY with keys:
- impactLevel (CRITICAL|HIGH|MEDIUM|LOW)
- disruptionRisk (CRITICAL|HIGH|MEDIUM|LOW)
- analysis (markdown string explaining operational impact, risks, syntax validity)
- rollbackCommands (array of string CLI commands to revert changes line-by-line).

STRICT ROLLBACK RULES:
1. Generate line-by-line inverse CLI commands in 'rollbackCommands'.
2. Invert 'no <cmd>' to '<cmd>' and '<cmd>' to 'no <cmd>'.
3. Invert 'shutdown' to 'no shutdown'.
4. Preserve context headers like 'interface Ethernet1/1' or 'line vty 0 15'.`;

        const userPrompt = `Vendor OS: ${vendorName}\n\nRunning Configuration Context:\n${configContext}\n\nProposed CLI Command:\n${cliCommand}`;

        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${GROQ_API_KEY}`,
          },
          body: JSON.stringify({
            model: GROQ_MODEL,
            response_format: { type: 'json_object' },
            temperature: 0.1,
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt },
            ],
          }),
        });

        if (groqRes.ok) {
          const groqData = await groqRes.json();
          const rawContent = (groqData.choices[0]?.message?.content || '{}')
            .replace(/```json/g, '')
            .replace(/```/g, '')
            .trim();
          parsedResult = JSON.parse(rawContent);
        }
      } catch (err) {
        console.warn('[!] Groq impact analysis failed, utilizing fallback:', err);
      }
    }

    const fallback = fallbackImpactAnalysis(cliCommand, vendorName);

    const finalImpactLevel = parsedResult?.impactLevel
      ? normalizeImpactLevel(parsedResult.impactLevel)
      : fallback.impactLevel;

    const finalDisruptionRisk = parsedResult?.disruptionRisk
      ? normalizeDisruptionRisk(parsedResult.disruptionRisk)
      : fallback.disruptionRisk;

    const rawRollback = Array.isArray(parsedResult?.rollbackCommands) && parsedResult.rollbackCommands.length > 0
      ? parsedResult.rollbackCommands
      : fallback.rollbackCommands;

    const rawNarrative = parsedResult?.analysis || 'CLI operational impact analysis completed.';

    // Construct unified Markdown payload
    const formattedMarkdown = buildFormattedMarkdown(
      vendorName,
      finalImpactLevel,
      finalDisruptionRisk,
      rawNarrative,
      rawRollback
    );

    return NextResponse.json({
      success: true,
      proposedCommand: cliCommand,
      impactLevel: finalImpactLevel,
      disruptionRisk: finalDisruptionRisk,
      analysis: formattedMarkdown,
      output: formattedMarkdown,
      summary: formattedMarkdown,
      rollbackCommands: rawRollback,
      // FIX: surfaced instead of silently 422-ing the request (see note above)
      promptInjectionFlagged: commandScan.flagged || configScan.flagged,
      promptInjectionSource: commandScan.flagged && configScan.flagged
        ? 'command_and_config'
        : commandScan.flagged
        ? 'command'
        : configScan.flagged
        ? 'config'
        : null,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal Server Error';
    console.error('[-] Error in /api/analyze-impact:', error);
    return NextResponse.json(
      { success: false, error: errorMessage },
      { status: 500 }
    );
  }
}
