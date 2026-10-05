// C:\Users\hp\aiops-securewatch\dashboard\app\api\scan\route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';
import {
  evaluateConfigDeterministically,
  detectVendor,
  ValidatedFinding
} from '@/lib/cisBenchmarks';
import { sanitizeConfig } from '@/lib/sanitizer';
import { scanForPromptInjection, wrapUntrustedContent } from '@/lib/security';

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface LlmAnalysisResult {
  summary: string;
  recommendations: string[];
  llmRiskLevel?: RiskLevel;
}

const RISK_RANKS: Record<RiskLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

function getHighestRiskLevel(riskA: RiskLevel, riskB: RiskLevel): RiskLevel {
  const rankA = RISK_RANKS[riskA] ?? 1;
  const rankB = RISK_RANKS[riskB] ?? 1;
  return rankA >= rankB ? riskA : riskB;
}

function normalizeRiskLevel(val?: string): RiskLevel {
  const normalized = String(val || '').toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized)) {
    return normalized as RiskLevel;
  }
  return 'LOW';
}

/**
 * FIX (hallucination ceiling): the hybrid calculation used to be
 * max(deterministic CIS floor, AI self-rated risk) with nothing else —
 * that stops the AI from UNDER-rating a config (it can never go below
 * the floor), but did nothing to stop it from OVER-rating one. An AI
 * that hallucinates "CRITICAL" on a config whose actual static findings
 * only justify LOW would previously flow straight through to the
 * Inventory tab unchecked.
 *
 * This clamps the AI's own contribution to at most one severity step
 * above the deterministic floor. The AI can still raise the risk above
 * the floor — it may have spotted something real that the static CIS
 * ruleset doesn't cover — but it can no longer single-handedly jump a
 * device from LOW to CRITICAL on self-rating alone. Every time this
 * clamp actually fires, it's logged and surfaced in the API response
 * (aiAnalysis.riskWasClamped) rather than silently corrected, so it's
 * visible during testing and explainable in a viva.
 */
function clampAiRiskToFloor(
  aiRisk: RiskLevel,
  floorRisk: RiskLevel
): { clamped: RiskLevel; wasClamped: boolean } {
  const floorRank = RISK_RANKS[floorRisk] ?? 1;
  const aiRank = RISK_RANKS[aiRisk] ?? 1;
  const ceilingRank = Math.min(4, floorRank + 1);

  if (aiRank <= ceilingRank) {
    return { clamped: aiRisk, wasClamped: false };
  }

  const rankToLevel = (rank: number): RiskLevel =>
    (Object.keys(RISK_RANKS) as RiskLevel[]).find((k) => RISK_RANKS[k] === rank) || 'LOW';

  return { clamped: rankToLevel(ceilingRank), wasClamped: true };
}

/** Checks if a config string is empty, null, or contains only exclamation marks/whitespace */
function isInvalidConfig(cfg?: string | null): boolean {
  if (!cfg || typeof cfg !== 'string') return true;
  const trimmed = cfg.trim();
  return trimmed === '' || /^[!\s]+$/.test(trimmed);
}

/**
 * Calls Groq/Llama for qualitative summary and recommendations.
 */
async function performLlmAnalysis(
  rawConfig: string,
  hostname: string,
  vendor: string,
  findings: ValidatedFinding[]
): Promise<LlmAnalysisResult> {
  const apiKey = process.env.GROQ_API_KEY;

  if (apiKey) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    try {
      const sanitized = sanitizeConfig(rawConfig);
      const truncatedConfig = sanitized.length > 12000
        ? sanitized.slice(0, 12000) + '\n...[TRUNCATED FOR LENGTH]...'
        : sanitized;

      const compressedFindings = findings.slice(0, 15).map(f => ({
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        description: f.description,
      }));

      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model:  'openai/gpt-oss-120b',
          messages: [
            {
              role: 'system',
              content:
                'You are a Principal Network Security Architect. Analyze the device configuration and static CIS audit findings. Provide a concise, high-impact Executive Summary (2-3 sentences analyzing systemic risk) and 3-5 vendor-specific hardening recommendations. Return ONLY valid JSON with keys: "summary" (string), "recommendations" (string array), and "riskLevel" ("CRITICAL"|"HIGH"|"MEDIUM"|"LOW"). ' +
                // FIX (real bug, confirmed by hand): the model recommended
                // "removing VLAN 999 from the trunk allowed-vlan list" on a
                // config where VLAN 999 was never in any trunk's allowed
                // list — it only appears as the access VLAN on one shut-down
                // port, which is the correct, standard way to park an unused
                // port, not a finding. The model pattern-matched on "unused
                // VLANs on trunks are bad" instead of reading the literal
                // config it was given.
                'Every claim and recommendation must be grounded strictly in the literal text of the running-configuration provided below — never state that a VLAN, interface, ACL, or feature appears somewhere in the config unless you can point to the exact line. Before recommending that a VLAN be removed from a trunk\'s allowed-vlan list, re-read that trunk interface\'s own "switchport trunk allowed vlan" line and confirm the VLAN number is actually present in it. If a port is administratively shut down and assigned to an otherwise-unused VLAN, that is a standard hardening pattern (a "blackhole" VLAN) — do not flag it as a gap.',
            },
            {
              role: 'user',
              // FIX: the raw device config is attacker-influenceable data,
              // not part of the operator's instructions. It's now wrapped
              // in an explicit untrusted-data boundary (see lib/security.ts)
              // instead of being concatenated straight into the prompt.
              content: `Device Context:\n- Hostname: ${hostname}\n- OS Platform: ${vendor}\n\nStatic CIS Audit Findings (${findings.length} total):\n${JSON.stringify(compressedFindings, null, 2)}\n\n${wrapUntrustedContent('running_configuration', truncatedConfig)}`,
            },
          ],
          // FIX: dropped from 0.1 to 0.0 to match analyze-firmware/route.ts's
          // Groq call. This endpoint's output (riskLevel, CIS-adjacent
          // findings narrative) is a classification/audit result, not
          // creative writing — identical input (same config, same vendor,
          // same static findings) should not flip between MEDIUM and HIGH
          // across runs. This is vendor-agnostic: the prompt and findings
          // payload are already built generically from whatever
          // detectVendor() resolves, for any of the 16 supported platforms,
          // so lowering temperature doesn't single out or change behavior
          // for any one vendor — it just makes the model's own self-rated
          // riskLevel more reproducible for all of them equally.
          temperature: 0.0,
          response_format: { type: 'json_object' },
        }),
      }).finally(() => clearTimeout(timeoutId));

      if (response.ok) {
        const data = await response.json();
        let rawContent = data.choices[0]?.message?.content || '{}';
        rawContent = rawContent.replace(/```json/g, '').replace(/```/g, '').trim();

        try {
          const content = JSON.parse(rawContent);
          return {
            summary: content.summary || 'AI Security Audit completed.',
            recommendations: Array.isArray(content.recommendations) ? content.recommendations : [],
            llmRiskLevel: normalizeRiskLevel(content.riskLevel),
          };
        } catch (parseErr) {
          console.warn('[!] Groq response JSON parse failed, falling back:', parseErr);
        }
      }
    } catch (err) {
      console.warn('[!] Groq API call timed out or failed, using fallback qualitative analysis:', err);
    }
  }

  return {
    summary: `Security assessment completed for target host ${hostname} running ${vendor}. Key control plane vulnerabilities detected.`,
    recommendations: [
      'Disable unencrypted management services (Telnet/HTTP) across all VRFs.',
      'Enforce SSHv2 protocol restriction and explicit line idle session timeouts.',
      'Verify centralized AAA/RADIUS authentication policies for administrative access.',
    ],
    llmRiskLevel: 'LOW',
  };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));

    const deviceId = body.deviceId || body.device_id;
    let scanId = body.scanId || body.scan_id;
    let configurationId = body.configurationId || body.configuration_id;
    let rawConfig = body.rawConfig || body.raw_config;

    if (!deviceId) {
      return NextResponse.json(
        { success: false, error: 'Missing required field: deviceId' },
        { status: 422 }
      );
    }

    const supabase = getSupabaseAdmin();
    let device: Record<string, any> = { hostname: 'Network-Device', vendor: 'generic' };

    if (supabase) {
      const { data: devData } = await supabase
        .from('devices')
        .select('*')
        .eq('id', deviceId)
        .maybeSingle();

      if (devData) {
        device = devData;

        // Priority 1: Check device record columns
        if (isInvalidConfig(rawConfig)) {
          const directConfig = devData.last_config || devData.raw_config || devData.config;
          if (!isInvalidConfig(directConfig)) {
            rawConfig = directConfig;
          }
        }
      }

      // Priority 2: Check configurations table with flexible column resolution
      if (isInvalidConfig(rawConfig)) {
        const { data: latestConfig } = await supabase
          .from('configurations')
          .select('*')
          .eq('device_id', deviceId)
          .order('created_at', { ascending: false })
          .limit(1)
          .maybeSingle();

        if (latestConfig) {
          rawConfig = latestConfig.raw_config ||
                     latestConfig.content ||
                     latestConfig.config ||
                     latestConfig.running_config ||
                     latestConfig.configuration || '';
          configurationId = latestConfig.id;
        }
      }

      // FIX (schema-confirmed bug): public.scans.configuration_id is NOT
      // NULL. configurationId only got set above when rawConfig had to be
      // fetched FROM the configurations table (Priority 2). When rawConfig
      // came straight from devices.last_config (Priority 1) — the normal
      // case, since the collector writes last_config on every successful
      // run — configurationId stayed undefined, and the insert further
      // down silently failed the NOT NULL constraint every time. We now
      // always resolve a configuration_id for this device if one isn't
      // already known, independent of where rawConfig itself came from.
      if (!configurationId) {
        const { data: idOnlyConfig } = await supabase
          .from('configurations')
          .select('id')
          .eq('device_id', deviceId)
          .order('created_at', { ascending: false })
          .limit(1)
          .maybeSingle();
        if (idOnlyConfig) {
          configurationId = idOnlyConfig.id;
        }
      }
    }

    // Validate configuration presence
    if (isInvalidConfig(rawConfig)) {
      return NextResponse.json(
        { success: false, error: 'No valid device configuration available to scan. Collect telemetry first.' },
        { status: 422 }
      );
    }

    const sanitizedPayload = sanitizeConfig(rawConfig);

    // FIX: This used to return 422 and refuse to audit the device whenever
    // the config text matched an injection signature. That's backwards for
    // a security tool: anyone who can write to the device's running-config
    // (e.g. via a separate compromise) can plant a matching phrase and make
    // this endpoint silently stop auditing that device — the exact device
    // that most needs auditing. We now flag it (goes into the saved scan
    // record and the response) and keep auditing. The LLM prompt itself
    // wraps the config in an explicit untrusted-data boundary so the model
    // is told never to treat it as instructions, which is the actual
    // mitigation — the regex scan is a detector/alert, not a gate.
    const injectionCheck = scanForPromptInjection(sanitizedPayload);

    const detectedPlatform = body.vendor || device.netmiko_type || device.vendor || 'cisco_xe';
    const vendorType = detectVendor(detectedPlatform);

    // 1. Evaluate configuration deterministically via static regex rules
    const cisResult = evaluateConfigDeterministically(sanitizedPayload, vendorType);
    const cisFloorRisk = normalizeRiskLevel(cisResult.riskLevel);
    const validatedFindings = cisResult.findings;

    // 2. Fetch qualitative executive summary & recommendations from LLM
    const aiAnalysis = await performLlmAnalysis(sanitizedPayload, device.hostname, vendorType, validatedFindings);

    // 3. Enforce Hybrid Risk Calculation: deterministic floor, then clamp
    // the AI's own self-rating so it can't inflate the result unchecked
    // (see clampAiRiskToFloor above).
    const rawAiRiskLevel = aiAnalysis.llmRiskLevel || 'LOW';
    const { clamped: clampedAiRiskLevel, wasClamped: riskWasClamped } = clampAiRiskToFloor(
      rawAiRiskLevel,
      cisFloorRisk
    );
    if (riskWasClamped) {
      console.warn(
        `[!] AI self-rated risk (${rawAiRiskLevel}) exceeded the deterministic floor (${cisFloorRisk}) by more than one level for device ${deviceId}; clamped to ${clampedAiRiskLevel}.`
      );
    }
    const overallRisk = getHighestRiskLevel(cisFloorRisk, clampedAiRiskLevel);
    const riskBadge = overallRisk === 'CRITICAL' ? '🔴 CRITICAL' : overallRisk === 'HIGH' ? '🟠 HIGH' : overallRisk === 'MEDIUM' ? '🟡 MEDIUM' : '🟢 LOW';

    const formattedMarkdownSummary =
`### 🛡️ Device Assessment Overview
* **Hostname:** ${device.hostname}
* **OS / Vendor:** \`${vendorType}\`
* **Static Findings:** ${validatedFindings.length} Benchmark Rules Violated
* **Overall Risk Rating:** ${riskBadge}${riskWasClamped ? `\n* **⚠️ AI Rating Overridden:** The AI self-rated this device as **${rawAiRiskLevel}**, which was more than one level above what the static findings justify. The displayed rating was capped to **${overallRisk}**, the highest level the static evidence currently supports.` : ''}${injectionCheck.flagged ? '\n* **⚠️ Integrity Alert:** This configuration contains text matching prompt-injection signatures. It was still fully audited below; treat this device as a priority for manual review, since the match itself can indicate tampering.' : ''}

---

### 📋 Executive Security Summary
> ${aiAnalysis.summary || 'Configuration assessment complete.'}

---

### 🚨 CIS Benchmark Violations (${validatedFindings.length})

${validatedFindings.length > 0
  ? validatedFindings.map((f: ValidatedFinding) =>
`**[${f.severity}] ${f.ruleId} — ${f.title}**
* **Framework Mapping:** ${f.cisControl || 'CIS Control Baseline'}
* **Risk Detail:** ${f.description}
* **Remediation CLI:**
\`\`\`cli
${f.remediationCli}
\`\`\``).join('\n\n---\n\n')
  : '✅ *No static CIS benchmark violations detected.*'}

---

### 💡 Hardening Action Items
${aiAnalysis.recommendations.map((r: string, idx: number) => `**${idx + 1}.** ${r}`).join('\n')}`;

    // FIX (schema-confirmed bug): public.scans has no `findings` column at
    // all — that key was silently rejected by every insert/update below
    // (caught by the try/catch, logged as non-fatal), so no finding from
    // any scan was ever actually persisted. Reloading the dashboard, or
    // opening a device the next day, only ever showed risk_level and the
    // markdown summary — the specific findings existed only in that one API
    // response and the client's in-memory cache. The schema already has a
    // `vulnerabilities` table built for exactly this (scan_id, title,
    // severity, description, remediation_cli) and useDashboard.ts already
    // reads from it — nothing ever wrote to it. That's fixed below.
    //
    // FIX: `configuration_id: configurationId || null` — scans.configuration_id
    // is NOT NULL, so this insert silently failed the constraint whenever
    // configurationId wasn't resolved (see the fix above). It's now guarded:
    // no configurationId means we skip the scans write entirely rather than
    // attempting (and losing) an insert the database will always reject.
    let savedScanId = scanId || null;
    let dbPersisted = false;
    let dbWarning: string | null = null;

    if (supabase) {
      try {
        const nowIso = new Date().toISOString();

        if (scanId) {
          await supabase
            .from('scans')
            .update({
              status: 'completed',
              risk_level: overallRisk,
              summary: formattedMarkdownSummary,
              updated_at: nowIso,
            })
            .eq('id', scanId);
          dbPersisted = true;
        } else if (configurationId) {
          const { data: inserted } = await supabase
            .from('scans')
            .insert({
              device_id: deviceId,
              configuration_id: configurationId,
              status: 'completed',
              risk_level: overallRisk,
              summary: formattedMarkdownSummary,
              created_at: nowIso,
              updated_at: nowIso,
            })
            .select('id')
            .maybeSingle();
          if (inserted) {
            savedScanId = inserted.id;
            dbPersisted = true;
          }
        } else {
          dbWarning = 'No configuration snapshot exists for this device (scans.configuration_id is required), so this scan result could not be saved to history. It is still shown below for this response only.';
          console.warn(`[!] Scan for ${deviceId} not persisted: no configuration_id available.`);
        }

        // Persist findings into the vulnerabilities table (scans has no
        // findings column — see fix note above). On an update, clear this
        // scan's previous findings first so re-scanning doesn't accumulate
        // duplicates.
        if (savedScanId && validatedFindings.length > 0) {
          if (scanId) {
            await supabase.from('vulnerabilities').delete().eq('scan_id', savedScanId);
          }
          const severityTitleCase = (level: string): string => {
            const normalized = (level || '').toUpperCase();
            const map: Record<string, string> = {
              CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low',
              INFORMATIONAL: 'Informational', SAFE: 'Safe',
            };
            // vulnerabilities.severity has a CHECK constraint on this exact
            // set of Title Case values; the CIS engine emits UPPERCASE.
            return map[normalized] || 'Informational';
          };
          const vulnRows = validatedFindings.map((f: any) => ({
            scan_id: savedScanId,
            title: f.title || f.ruleId || 'Untitled finding',
            severity: severityTitleCase(f.severity),
            description: f.description || null,
            affected_config_line: f.affectedConfigLine || f.affected_config_line || null,
            remediation_cli: f.remediationCli || f.remediation_cli || null,
          }));
          const { error: vulnErr } = await supabase.from('vulnerabilities').insert(vulnRows);
          if (vulnErr) {
            console.warn('[!] Non-fatal error writing vulnerabilities:', vulnErr);
          }
        }

        // Update device risk level and ensure last_config stays populated
        try {
          await supabase
            .from('devices')
            .update({
              risk_level: overallRisk,
              last_config: rawConfig,
            })
            .eq('id', deviceId);
        } catch (devErr) {
          console.warn('[!] Non-fatal error updating device record:', devErr);
        }

      } catch (dbErr) {
        console.warn('[!] Scan DB record write error:', dbErr);
        dbWarning = 'Scan completed but could not be fully saved to the database.';
      }
    }

    return NextResponse.json({
      success: true,
      scanId: savedScanId,
      deviceId,
      riskLevel: overallRisk,
      summary: formattedMarkdownSummary,
      output: formattedMarkdownSummary,
      sanitizedConfig: sanitizedPayload,
      findings: validatedFindings,
      // FIX: surfaced instead of silently gating the whole scan (see note above)
      promptInjectionFlagged: injectionCheck.flagged,
      promptInjectionMatches: (injectionCheck as any).matchedSignatures ?? injectionCheck.matches ?? [],
      dbPersisted,
      dbWarning,
      aiAnalysis: {
        riskLevel: overallRisk,
        // FIX: surfaced so the UI (and you, in a viva) can show exactly
        // what the AI said on its own vs. what was actually displayed,
        // instead of the clamp being an invisible server-side detail.
        rawAiRiskLevel,
        cisFloorRisk,
        riskWasClamped,
        summary: aiAnalysis.summary,
        recommendations: aiAnalysis.recommendations,
        rawFindings: validatedFindings,
      },
    });
  } catch (err: any) {
    console.error('[-] Error executing scan in /api/scan:', err);
    return NextResponse.json(
      { success: false, error: err?.message || 'Internal Server Error' },
      { status: 500 }
    );
  }
}