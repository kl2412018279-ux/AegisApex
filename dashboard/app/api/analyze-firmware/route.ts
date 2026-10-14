// dashboard/app/api/analyze-firmware/route.ts
// OS / firmware assessment.
//   * CVEs: deterministic NVD lookup by CPE (platform + version), optional
//     Cisco PSIRT advisories, and AI-suggested ids only after NVD confirms
//     they apply. Each is enriched with CISA KEV and FIRST EPSS.
//   * Risk floor: computed from those CVEs + EOL text (lib/vulnIntel.ts).
//     The AI can raise it by at most one step, never above a LOW floor.
//   * AI: lifecycle narrative and recommended release train only.
import { NextRequest, NextResponse } from 'next/server';
import { detectVendor, type VendorType } from '@/lib/cisBenchmarks';
import { requireUser, requireDevice } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { enforceRateLimit } from '@/lib/rateLimit';
import { FirmwareBody } from '@/lib/validation';
import { readJson, routeError, HttpError } from '@/lib/http';
import { groqJson } from '@/lib/groq';
import { clampAiRiskToFloor, getHighestRiskLevel, normalizeRiskLevel, riskBadge, type RiskLevel } from '@/lib/risk';
import { lookupVulnerabilities, firmwareRiskFloor, type CveRecord } from '@/lib/vulnIntel';
import { recordRisk } from '@/lib/riskHistory';
import { queueAlert } from '@/lib/alerts';
import { wrapUntrustedContent } from '@/lib/security';

interface AiFirmware {
  riskLevel?: string;
  summary?: string;
  cves?: unknown;
  recommendations?: unknown;
  targetFirmware?: string;
  eolStatus?: string;
}

const SYSTEM_PROMPT = [
  'You are an expert network OS and firmware vulnerability auditor. Analyze the provided "show version" output for OS version, EOL/EOS status, and CVEs SPECIFIC to the indicated vendor/OS platform.',
  'Return ONLY valid JSON with keys: riskLevel (CRITICAL|HIGH|MEDIUM|LOW), summary (string), cves (string array), recommendations (string array), targetFirmware (string), eolStatus (string).',
  'targetFirmware and eolStatus are REQUIRED. targetFirmware names the vendor\'s current recommended/LTS release train for the EXACT platform (e.g. "Cisco IOS-XE 17.9.x LTS", "FortiOS 7.4.x"). eolStatus is "Active / Supported" or "End-of-Life (EOL)" for the DETECTED version.',
  'Only if the platform cannot be identified at all, return targetFirmware "Unable to determine (unidentified platform)" and eolStatus "Unknown — verify with vendor".',
  // Every id is verified against NVD afterwards, but prevention beats filtering:
  // the model has returned real Cisco CVEs for the wrong product line before.
  'cves must only contain CVE identifiers you are confident are real and apply to this exact vendor, platform, hardware family and version. Never invent or approximate an id, and never use a vendor advisory number as a CVE id. An empty array is the correct answer when unsure.',
].join(' ');

// Offline fallback recommendations, used only when the AI is unavailable.
const FALLBACK_RECOMMENDATIONS: Record<VendorType, string[]> = {
  cisco_ios: ['Enforce SSHv2 and restrict line vty access lists.', 'Disable the HTTP/HTTPS web UI if unused.'],
  cisco_nxos: ['Disable feature telnet / feature http-server.', 'Restrict management access to the mgmt0 VRF with an ACL.'],
  cisco_xr: ['Restrict management plane protection (MPP) to trusted interfaces.', 'Disable unused XML/NETCONF agents.'],
  juniper: ['Disable Telnet and keep SSH-only system services.', 'Use sha-512 password format for local accounts.'],
  arista: ['Disable the HTTP management API protocol, keep HTTPS only.', 'Use TACACS+/RADIUS rather than local-only accounts.'],
  fortinet: ['Restrict SSL-VPN and admin GUI exposure to trusted source IPs.', 'Enable two-factor authentication for administrators.'],
  paloalto: ['Disable Telnet/HTTP management (disable-telnet / disable-http).', 'Use a dedicated authentication profile for administrators.'],
  huawei: ['Disable the Telnet server and enforce Stelnet/SSH.', 'Configure an AAA authentication scheme beyond local-only.'],
  aruba_hpe: ['Disable cleartext REST API management on the default VRF.', 'Verify RADIUS failover for local accounts.'],
  dell_os10: ['Enforce TLS 1.2+ on RESTCONF endpoints.', 'Restrict administrative access via a management VRF policy.'],
  f5_tmsh: ['Restrict sshd to SSHv2.', 'Keep the management interface on an out-of-band network.'],
  nokia_sros: ['Shut down Telnet and enforce SSH only.', 'Use hash2 password storage for local accounts.'],
  vyos: ['Delete the Telnet service and keep SSH only.', 'Use RADIUS/TACACS+ rather than local-only accounts.'],
  extreme_exos: ['Disable Telnet and the web UI.', 'Enable AAA rather than local-only accounts.'],
  mikrotik: ['Disable the telnet and www services.', 'Use RADIUS-backed authentication for administrators.'],
  generic: ['Check hardware lifecycle with the manufacturer.', 'Audit management interfaces for unencrypted protocols.'],
};

/** First dotted number pair in each string, compared at train level (major.minor). */
function compareInstalledToTarget(installed: string, target: string): 'newer' | 'same' | 'older' | 'unknown' {
  const parts = (t: string) => {
    const m = t.match(/version[:\s]+v?(\d+(?:\.\d+){1,3})/i) || t.match(/(\d+(?:\.\d+){1,3})/);
    return m ? m[1].split('.').map((n) => parseInt(n, 10)) : null;
  };
  const a = parts(installed);
  const b = parts(target);
  if (!a || !b) return 'unknown';
  for (let i = 0; i < Math.min(2, a.length, b.length); i++) {
    if (a[i] > b[i]) return 'newer';
    if (a[i] < b[i]) return 'older';
  }
  return 'same';
}

function cveLine(c: CveRecord): string {
  const tags = [
    c.kev ? `🚨 **ACTIVELY EXPLOITED** (CISA KEV since ${c.kevDateAdded}${c.kevRansomware ? ', used in ransomware' : ''})` : null,
    c.cvssScore != null ? `CVSS ${c.cvssScore}${c.cvssSeverity ? ` ${c.cvssSeverity}` : ''}` : null,
    c.epss != null ? `EPSS ${(c.epss * 100).toFixed(1)}%` : null,
  ].filter(Boolean);
  const desc = c.description ? c.description.slice(0, 280) + (c.description.length > 280 ? '…' : '') : '_No NVD description available; verify manually._';
  const link = c.advisoryUrl || `https://nvd.nist.gov/vuln/detail/${c.id}`;
  return `* **[${c.id}](${link})** — ${tags.join(' · ')}\n  ${desc}`;
}

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'operator');
    const body = FirmwareBody.parse(await readJson(req));
    await enforceRateLimit(ctx.admin, ctx.userId, 'ai-firmware', 20);
    const device = await requireDevice(ctx, body.deviceId, 'operator');
    const admin = ctx.admin;

    const rawVersion = body.rawVersion || device.raw_version || '';
    if (!rawVersion.trim()) throw new HttpError(422, 'No "show version" output for this device. Collect telemetry first.');
    const vendorType = detectVendor(body.vendor || device.netmiko_type || device.vendor || 'cisco_ios');
    const hostname = device.hostname || 'Network-Device';

    const ai = await groqJson<AiFirmware>({
      label: 'firmware',
      system: SYSTEM_PROMPT,
      user: `Device Context:\n- Hostname: ${hostname}\n- Vendor / OS Platform: ${vendorType}\n\n${wrapUntrustedContent('show_version', rawVersion.slice(0, 8000))}`,
      timeoutMs: 20000,
    });
    const aiCves = Array.isArray(ai?.data.cves) ? (ai!.data.cves as unknown[]).map(String) : [];
    const intel = await lookupVulnerabilities(vendorType, rawVersion, aiCves);

    const floor = firmwareRiskFloor(rawVersion, intel.cves);
    const aiRisk = ai ? normalizeRiskLevel(ai.data.riskLevel, 'MEDIUM') : floor;
    const { clamped, wasClamped } = clampAiRiskToFloor(aiRisk, floor);
    const riskLevel: RiskLevel = getHighestRiskLevel(floor, clamped);

    const targetFirmware = ai?.data.targetFirmware?.trim() || 'Unavailable (AI offline, retry)';
    const eolStatus = ai?.data.eolStatus?.trim() || 'Unavailable (AI offline, retry)';
    const aiRecs = Array.isArray(ai?.data.recommendations) ? (ai!.data.recommendations as unknown[]).map(String) : FALLBACK_RECOMMENDATIONS[vendorType];

    // One upgrade line built from targetFirmware so it can't contradict the
    // hero card, and never "upgrade" to a train older than what's installed.
    const comparison = compareInstalledToTarget(rawVersion, targetFirmware);
    const upgradeLine = !ai
      ? null
      : comparison === 'newer'
      ? `The installed release is **newer** than the recommended train (**${targetFirmware}**); no upgrade needed. Confirm the installed train is still supported.`
      : comparison === 'same'
      ? `The installed release is on the recommended train (**${targetFirmware}**). Apply the latest maintenance patch for that train.`
      : `Upgrade to the vendor's recommended release, **${targetFirmware}**.`;
    const recommendations = [
      ...(upgradeLine ? [upgradeLine] : []),
      ...aiRecs.filter((r) => !(/upgrade|update/i.test(r) && /\d+\.\d+/.test(r))),
    ];

    const kevCount = intel.cves.filter((c) => c.kev).length;
    const shown = intel.cves.slice(0, 25);
    const cveSection = intel.cves.length
      ? `${kevCount ? `> 🚨 **${kevCount} of these are being actively exploited (CISA KEV). Patch these first.**\n\n` : ''}${shown.map(cveLine).join('\n')}${
          intel.cves.length > shown.length ? `\n\n_…and ${intel.cves.length - shown.length} more (ranked lower by exploitation and severity)._` : ''
        }`
      : intel.cpe
      ? '✅ *NVD lists no CVEs for this exact platform and version.*'
      : '⚠️ *This platform/version could not be mapped to a CPE name, so only AI-suggested CVEs (NVD-verified) were checked.*';

    const osSummary = `### 🔍 OS/Firmware Security Assessment
${!ai ? '\n> ⚠️ **AI service unavailable.** Lifecycle data below is not available; CVE data comes from NVD and is still valid.\n' : ''}
* **Hostname:** ${hostname}
* **Platform:** ${intel.platform ? `${intel.platform.label} ${intel.platform.version}${intel.platform.update ? ` ${intel.platform.update}` : ''}` : `\`${vendorType}\``}
* **Evaluated Threat Level:** **${riskBadge(riskLevel)}**${wasClamped ? `\n* **⚠️ AI Rating Overridden:** the AI rated this **${aiRisk}**; capped at **${riskLevel}**, the highest the evidence supports.` : ''}
* **Known CVEs:** ${intel.cves.length}${kevCount ? ` (**${kevCount} actively exploited**)` : ''}
* **Recommended Release:** ${targetFirmware}
* **Lifecycle Status:** ${eolStatus}
* **Sources:** ${intel.sourcesQueried.join(', ') || 'none'}${intel.cpe ? ` · \`${intel.cpe}\`` : ''}${intel.errors.length ? `\n* **⚠️ Partial data:** ${intel.errors.join('; ')}` : ''}

---

### 📋 Executive OS Assessment
> ${ai?.data.summary || 'AI narrative unavailable.'}

---

### 🚨 Known Vulnerabilities (${intel.cves.length})

${cveSection}

---

### 💡 Lifecycle & Hardening Recommendations
${recommendations.map((r, i) => `**${i + 1}.** ${r}`).join('\n')}`;

    // Persist onto the latest scan row (create one if the device has none).
    let dbWarning: string | null = null;
    const now = new Date().toISOString();
    const fields = { status: 'completed', risk_level: riskLevel, os_summary: osSummary, target_firmware: targetFirmware, eol_status: eolStatus, cve_details: intel.cves, updated_at: now };
    const { data: latestScan } = await admin.from('scans').select('id').eq('device_id', device.id).order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (latestScan) {
      await admin.from('scans').update(fields).eq('id', latestScan.id);
    } else {
      const { data: latestConfig } = await admin.from('configurations').select('id').eq('device_id', device.id).order('created_at', { ascending: false }).limit(1).maybeSingle();
      let configurationId = latestConfig?.id ?? null;
      if (!configurationId && device.last_config) {
        const { data: created } = await admin.from('configurations').insert({ device_id: device.id, raw_config: device.last_config, source: 'manual' }).select('id').single();
        configurationId = created?.id ?? null;
      }
      if (configurationId) {
        await admin.from('scans').insert({ device_id: device.id, configuration_id: configurationId, summary: 'OS firmware analysis saved.', created_at: now, ...fields });
      } else {
        dbWarning = 'No configuration snapshot exists for this device yet, so the firmware analysis could not be saved. Collect telemetry first.';
      }
    }

    // Alert on newly exploited CVEs: compare against the previous analysis.
    if (kevCount) {
      const { data: prior } = await admin.from('risk_history').select('kev_count').eq('device_id', device.id).eq('source', 'firmware').order('recorded_at', { ascending: false }).limit(1).maybeSingle();
      if ((prior?.kev_count ?? 0) < kevCount) {
        await queueAlert(admin, {
          orgId: device.org_id,
          deviceId: device.id,
          kind: 'kev_detected',
          severity: riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
          title: `${hostname} runs firmware with ${kevCount} actively exploited CVE(s)`,
          body: intel.cves.filter((c) => c.kev).slice(0, 10).map((c) => `• ${c.id} (CVSS ${c.cvssScore ?? '?'}) — KEV due ${c.kevDueDate}`).join('\n'),
        });
      }
    }
    await recordRisk(admin, { deviceId: device.id, riskLevel, source: 'firmware', cveCount: intel.cves.length, kevCount });
    await audit(ctx, { action: 'scan.firmware', orgId: device.org_id, targetType: 'device', targetId: device.id, details: { riskLevel, cves: intel.cves.length, kev: kevCount } });

    return NextResponse.json({
      success: true,
      deviceId: device.id,
      riskLevel,
      osSummary,
      output: osSummary,
      summary: osSummary,
      cves: intel.cves.map((c) => c.id),
      cveDetails: intel.cves,
      cpe: intel.cpe,
      kevCount,
      targetFirmware,
      eolStatus,
      aiAnalysis: { rawAiRiskLevel: aiRisk, staticFloorRisk: floor, riskWasClamped: wasClamped, usedFallback: !ai },
      dataErrors: intel.errors,
      dbPersisted: !dbWarning,
      dbWarning,
    });
  } catch (err) {
    return routeError(err, 'POST /api/analyze-firmware');
  }
}
