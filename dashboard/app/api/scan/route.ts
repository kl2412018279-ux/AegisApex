// dashboard/app/api/scan/route.ts
// Configuration audit: deterministic CIS rules decide the risk floor, the
// LLM adds an executive summary and may raise the rating by at most one
// step (never above the evidence when the floor is LOW).
import { NextRequest, NextResponse } from 'next/server';
import { evaluateConfigDeterministically, detectVendor, FRAMEWORK_LABELS, type ValidatedFinding } from '@/lib/cisBenchmarks';
import { sanitizeConfig } from '@/lib/sanitizer';
import { scanForPromptInjection, wrapUntrustedContent } from '@/lib/security';
import { requireUser, requireDevice } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { enforceRateLimit } from '@/lib/rateLimit';
import { ScanBody } from '@/lib/validation';
import { readJson, routeError, HttpError } from '@/lib/http';
import { groqJson } from '@/lib/groq';
import { clampAiRiskToFloor, getHighestRiskLevel, normalizeRiskLevel, riskBadge, severityTitleCase, type RiskLevel } from '@/lib/risk';
import { recordRisk } from '@/lib/riskHistory';

interface LlmAnalysis {
  summary: string;
  recommendations: string[];
  llmRiskLevel: RiskLevel;
  aiAvailable: boolean;
}

const SYSTEM_PROMPT = [
  'You are a Principal Network Security Architect. Analyze the device configuration and static CIS audit findings.',
  'Provide a concise Executive Summary (2-3 sentences on systemic risk) and 3-5 vendor-specific hardening recommendations.',
  'Return ONLY valid JSON with keys: "summary" (string), "recommendations" (string array), and "riskLevel" ("CRITICAL"|"HIGH"|"MEDIUM"|"LOW").',
  // The model once recommended removing a VLAN from a trunk it was never on.
  'Every claim must be grounded in the literal configuration text below — never say a VLAN, interface, ACL or feature appears somewhere unless you can quote the exact command or interface it appears under.',
  'Before recommending that a VLAN be removed from a trunk, re-read that trunk\'s own "switchport trunk allowed vlan" line and confirm the VLAN is present.',
  'A shut-down port assigned to an otherwise unused VLAN is a standard "blackhole VLAN" hardening pattern, not a gap.',
  // The model was never given line numbers, so any it cites are invented.
  'You are NOT given line numbers, so NEVER cite one. Point to configuration by quoting the interface name or command text instead.',
].join(' ');

const LINE_CITATION_RE = /\s*\(?\s*lines?\s+\d+\s*(?:[-–‑]\s*\d+)?[^)]*\)?/gi;

/** Safety net for the no-line-numbers instruction: strip and log any that slip through. */
function stripFabricatedLineCitations(recommendations: string[]): string[] {
  return recommendations.map((rec) => {
    const cleaned = rec.replace(LINE_CITATION_RE, '').replace(/\s{2,}/g, ' ').trim();
    if (cleaned !== rec.trim()) console.warn(`[!] Stripped a fabricated line citation from an AI recommendation: "${rec}"`);
    return cleaned || rec;
  });
}

function isInvalidConfig(cfg?: string | null): boolean {
  return !cfg || !cfg.trim() || /^[!\s]+$/.test(cfg.trim());
}

async function performLlmAnalysis(sanitizedConfig: string, hostname: string, vendor: string, findings: ValidatedFinding[]): Promise<LlmAnalysis> {
  const truncated = sanitizedConfig.length > 12000 ? `${sanitizedConfig.slice(0, 12000)}\n...[TRUNCATED FOR LENGTH]...` : sanitizedConfig;
  const compressed = findings.slice(0, 15).map(({ ruleId, title, severity, description }) => ({ ruleId, title, severity, description }));

  const result = await groqJson<{ summary?: string; recommendations?: unknown; riskLevel?: string }>({
    label: 'config',
    system: SYSTEM_PROMPT,
    user: `Device Context:\n- Hostname: ${hostname}\n- OS Platform: ${vendor}\n\nStatic CIS Audit Findings (${findings.length} total):\n${JSON.stringify(compressed, null, 2)}\n\n${wrapUntrustedContent('running_configuration', truncated)}`,
    temperature: 0,
    timeoutMs: 15000,
  });

  if (result) {
    const recs = Array.isArray(result.data.recommendations) ? result.data.recommendations.map(String) : [];
    return {
      summary: result.data.summary || 'AI Security Audit completed.',
      recommendations: stripFabricatedLineCitations(recs),
      llmRiskLevel: normalizeRiskLevel(result.data.riskLevel),
      aiAvailable: true,
    };
  }
  return {
    summary: 'The AI service was unavailable, so this summary is a generic baseline. The CIS rule findings and risk level below come from the rule engine and are still accurate.',
    recommendations: [
      'Disable unencrypted management services (Telnet/HTTP) across all VRFs.',
      'Enforce SSHv2 and explicit idle session timeouts on every management line.',
      'Verify centralized AAA (TACACS+/RADIUS) for administrative access.',
    ],
    llmRiskLevel: 'LOW',
    aiAvailable: false,
  };
}

function frameworkLine(f: ValidatedFinding): string {
  if (!f.frameworks) return '';
  const parts = (Object.keys(FRAMEWORK_LABELS) as Array<keyof typeof FRAMEWORK_LABELS>)
    .filter((k) => f.frameworks![k].length)
    .map((k) => `${FRAMEWORK_LABELS[k]} ${f.frameworks![k].join(', ')}`);
  return parts.length ? `\n* **Compliance:** ${parts.join(' · ')}` : '';
}

function buildMarkdown(args: {
  hostname: string;
  vendor: string;
  overallRisk: RiskLevel;
  rawAiRisk: RiskLevel;
  clamped: boolean;
  injectionFlagged: boolean;
  findings: ValidatedFinding[];
  rulesEvaluated: number;
  ai: LlmAnalysis;
}): string {
  const { findings } = args;
  const violations = findings.length
    ? findings
        .map(
          (f) => `**[${f.severity}] ${f.ruleId} — ${f.title}**
* **Control:** ${f.cisControl || 'CIS Controls v8'}${frameworkLine(f)}
* **Risk Detail:** ${f.description}${f.evidence ? `\n* **Evidence:** \`${f.evidence.replace(/`/g, "'")}\`` : ''}
* **Remediation CLI:**
\`\`\`cli
${f.remediationCli}
\`\`\``
        )
        .join('\n\n---\n\n')
    : '✅ *No static CIS benchmark violations detected.*';

  // Action items quote each finding's own vetted remediation command rather
  // than the LLM's paraphrase (which once "fixed" disable-HTTP by enabling HTTPS).
  const actions = findings.length
    ? findings
        .map((f, i) => (f.remediationCli.includes('\n') ? `**${i + 1}.** ${f.title}\n\`\`\`cli\n${f.remediationCli}\n\`\`\`` : `**${i + 1}.** ${f.title} — \`${f.remediationCli}\``))
        .join('\n')
    : args.ai.recommendations.map((r, i) => `**${i + 1}.** ${r}`).join('\n');

  return `### 🛡️ Device Assessment Overview
* **Hostname:** ${args.hostname}
* **OS / Vendor:** \`${args.vendor}\`
* **Static Findings:** ${findings.length} of ${args.rulesEvaluated} applicable rules violated
* **Overall Risk Rating:** ${riskBadge(args.overallRisk)}${
    args.clamped
      ? `\n* **⚠️ AI Rating Overridden:** The AI self-rated this device **${args.rawAiRisk}**, more than the static findings justify. The rating was capped at **${args.overallRisk}**.`
      : ''
  }${
    args.injectionFlagged
      ? '\n* **⚠️ Integrity Alert:** This configuration contains text matching prompt-injection signatures. It was still fully audited; review this device manually, since the match itself can indicate tampering.'
      : ''
  }

---

### 📋 Executive Security Summary
> ${args.ai.summary || 'Configuration assessment complete.'}

---

### 🚨 CIS Benchmark Violations (${findings.length})

${violations}

---

### 💡 Hardening Action Items
${actions}`;
}

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'operator');
    const body = ScanBody.parse(await readJson(req));
    enforceRateLimit(ctx.userId, 'ai-scan', 20);
    const device = await requireDevice(ctx, body.deviceId, 'operator');
    const admin = ctx.admin;

    // Config source, most explicit first: request body, devices row, latest snapshot.
    let rawConfig = body.rawConfig;
    let configurationId = body.configurationId ?? null;
    if (isInvalidConfig(rawConfig) && !isInvalidConfig(device.last_config)) rawConfig = device.last_config;
    if (isInvalidConfig(rawConfig) || !configurationId) {
      const { data: latest } = await admin
        .from('configurations')
        .select('id, raw_config, content')
        .eq('device_id', device.id)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (latest) {
        if (isInvalidConfig(rawConfig)) rawConfig = latest.raw_config || latest.content || '';
        configurationId = configurationId || latest.id;
      }
    }
    if (isInvalidConfig(rawConfig)) throw new HttpError(422, 'No valid device configuration available to scan. Collect telemetry first.');
    const config = rawConfig as string;

    // scans.configuration_id is NOT NULL: create a snapshot for devices whose
    // config was seeded directly onto devices.last_config.
    if (!configurationId) {
      const { data: created } = await admin
        .from('configurations')
        .insert({ device_id: device.id, raw_config: config, source: 'manual' })
        .select('id')
        .single();
      configurationId = created?.id ?? null;
    }

    const sanitized = sanitizeConfig(config);
    // A detector, not a gate: refusing to audit on a match would let anyone
    // who can write to the config switch auditing off for that device.
    const injection = scanForPromptInjection(sanitized);

    const vendorType = detectVendor(body.vendor || device.netmiko_type || device.vendor || 'cisco_xe');
    // Rules run on the raw config server-side; evidence comes back redacted.
    const cis = evaluateConfigDeterministically(config, vendorType);
    const floor = normalizeRiskLevel(cis.riskLevel);
    const ai = await performLlmAnalysis(sanitized, device.hostname, vendorType, cis.findings);
    const { clamped, wasClamped } = clampAiRiskToFloor(ai.llmRiskLevel, floor);
    if (wasClamped) console.warn(`[!] AI risk ${ai.llmRiskLevel} clamped to ${clamped} (floor ${floor}) for ${device.id}`);
    const overallRisk = getHighestRiskLevel(floor, clamped);

    const summary = buildMarkdown({
      hostname: device.hostname,
      vendor: vendorType,
      overallRisk,
      rawAiRisk: ai.llmRiskLevel,
      clamped: wasClamped,
      injectionFlagged: injection.flagged,
      findings: cis.findings,
      rulesEvaluated: cis.rulesEvaluated,
      ai,
    });

    let savedScanId = body.scanId ?? null;
    let dbWarning: string | null = null;
    const now = new Date().toISOString();
    if (savedScanId) {
      const { error } = await admin
        .from('scans')
        .update({ status: 'completed', risk_level: overallRisk, summary, rules_evaluated: cis.rulesEvaluated, updated_at: now })
        .eq('id', savedScanId)
        .eq('device_id', device.id);
      if (error) dbWarning = `Scan could not be saved: ${error.message}`;
    } else if (configurationId) {
      const { data: inserted, error } = await admin
        .from('scans')
        .insert({
          device_id: device.id,
          configuration_id: configurationId,
          status: 'completed',
          risk_level: overallRisk,
          summary,
          rules_evaluated: cis.rulesEvaluated,
          model_used: ai.aiAvailable ? 'cis-rules + groq' : 'cis-rules',
          created_at: now,
          updated_at: now,
        })
        .select('id')
        .single();
      if (error) dbWarning = `Scan could not be saved: ${error.message}`;
      savedScanId = inserted?.id ?? null;
    }

    if (savedScanId) {
      await admin.from('vulnerabilities').delete().eq('scan_id', savedScanId);
      if (cis.findings.length) {
        const { error } = await admin.from('vulnerabilities').insert(
          cis.findings.map((f) => ({
            scan_id: savedScanId,
            rule_id: f.ruleId,
            title: f.title,
            severity: severityTitleCase(f.severity),
            description: f.description,
            evidence: f.evidence ?? null,
            frameworks: f.frameworks ?? null,
            remediation_cli: f.remediationCli,
          }))
        );
        if (error) console.warn('[!] vulnerabilities insert failed:', error.message);
      }
    }

    await admin.from('devices').update({ risk_level: overallRisk, last_config: config }).eq('id', device.id);
    await recordRisk(admin, {
      deviceId: device.id,
      riskLevel: overallRisk,
      source: 'config',
      findingsCount: cis.findings.length,
      rulesEvaluated: cis.rulesEvaluated,
    });
    await audit(ctx, { action: 'scan.config', orgId: device.org_id, targetType: 'device', targetId: device.id, details: { riskLevel: overallRisk, findings: cis.findings.length } });

    return NextResponse.json({
      success: true,
      scanId: savedScanId,
      deviceId: device.id,
      riskLevel: overallRisk,
      summary,
      output: summary,
      findings: cis.findings,
      rulesEvaluated: cis.rulesEvaluated,
      promptInjectionFlagged: injection.flagged,
      promptInjectionMatches: injection.matches ?? [],
      dbPersisted: !!savedScanId && !dbWarning,
      dbWarning,
      aiAnalysis: {
        riskLevel: overallRisk,
        rawAiRiskLevel: ai.llmRiskLevel,
        cisFloorRisk: floor,
        riskWasClamped: wasClamped,
        aiAvailable: ai.aiAvailable,
        summary: ai.summary,
        recommendations: ai.recommendations,
      },
    });
  } catch (err) {
    return routeError(err, 'POST /api/scan');
  }
}
