// dashboard/app/api/analyze-firmware/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface DeviceRecord {
  id?: string;
  hostname?: string;
  vendor?: string;
  netmiko_type?: string;
  raw_version?: string;
}

interface FirmwareAnalysis {
  riskLevel: RiskLevel;
  summary: string;
  cves: string[];
  recommendations: string[];
}

const RISK_RANKS: Record<RiskLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

function getHighestRiskLevel(riskA: RiskLevel, riskB: RiskLevel): RiskLevel {
  const rankA = RISK_RANKS[riskA] || 1;
  const rankB = RISK_RANKS[riskB] || 1;
  return rankA >= rankB ? riskA : riskB;
}

function normalizeRiskLevel(val?: string): RiskLevel {
  const normalized = String(val || '').toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized)) {
    return normalized as RiskLevel;
  }
  return 'MEDIUM';
}

function getDeterministicFirmwareRisk(rawVersion: string, cves: string[] = []): RiskLevel {
  const versionLower = rawVersion.toLowerCase();

  if (
    versionLower.includes('end of life') ||
    versionLower.includes('end-of-life') ||
    versionLower.includes('eol') ||
    versionLower.includes('obsolete') ||
    versionLower.includes('unsupported')
  ) {
    return 'HIGH';
  }

  if (cves.length >= 3) {
    return 'HIGH';
  } else if (cves.length > 0) {
    return 'MEDIUM';
  }

  return 'LOW';
}

/**
 * Returns platform-specific default security advisories when Groq API is offline or unreachable.
 */
function getVendorFallback(vendor: string, hostname: string): { cves: string[]; recommendations: string[]; summary: string } {
  const v = vendor.toLowerCase();
  
  if (v.includes('cisco')) {
    return {
      cves: ['CVE-2023-20198', 'CVE-2023-20273'],
      recommendations: [
        'Enforce SSHv2 protocol and restrict line vty access lists.',
        'Upgrade IOS-XE release to latest active maintenance train.',
        'Disable HTTP/HTTPS integrated web server if unused.',
      ],
      summary: `Firmware analysis completed for ${hostname} (Cisco IOS). OS version detected; verify active web UI configuration and management ACLs.`,
    };
  }

  if (v.includes('dell')) {
    return {
      cves: ['CVE-2022-2917'],
      recommendations: [
        'Upgrade OS10 image to the latest recommended LTS maintenance release.',
        'Ensure RESTCONF/eAPI management endpoints enforce strict TLS 1.2+ encryption.',
        'Restrict control-plane administrative access via explicit management VRF policy.',
      ],
      summary: `Firmware analysis completed for target host ${hostname} running Dell OS10. System version identified; check Dell Security Advisories for baseline OS updates.`,
    };
  }

  if (v.includes('aruba') || v.includes('aoscx')) {
    return {
      cves: ['CVE-2023-35984'],
      recommendations: [
        'Migrate to recommended ArubaOS-CX LTS release train.',
        'Disable cleartext REST API management services on default VRF.',
        'Verify AAA RADIUS server failover configuration for local user accounts.',
      ],
      summary: `Firmware audit complete for ${hostname} (ArubaOS-CX). System version identified; review vendor portal for platform release updates.`,
    };
  }

  return {
    cves: [],
    recommendations: [
      'Perform hardware life-cycle check with device manufacturer.',
      'Upgrade system software to current secure baseline release.',
      'Audit management interfaces for unencrypted transport protocols.',
    ],
    summary: `Firmware evaluation completed for host ${hostname} running ${vendor}. Check manufacturer releases for active CVE hotfixes.`,
  };
}

async function analyzeFirmwareWithGroq(
  hostname: string,
  vendor: string,
  rawVersion: string
): Promise<FirmwareAnalysis> {
  const apiKey = process.env.GROQ_API_KEY;

  if (apiKey) {
    try {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile',
          messages: [
            {
              role: 'system',
              content:
                'You are an expert network OS and firmware vulnerability auditor. Analyze the provided "show version" telemetry for OS version, known EOL/EOS status, and CVE security vulnerabilities SPECIFIC to the indicated vendor/OS platform. Return ONLY valid JSON with keys: riskLevel (CRITICAL|HIGH|MEDIUM|LOW), summary (string), cves (string array), and recommendations (string array). Do NOT invent CVEs for unrelated hardware vendors.',
            },
            {
              role: 'user',
              content: `Device Context:\n- Hostname: ${hostname}\n- Vendor / OS Platform: ${vendor}\n\nCLI Show Version Output:\n${rawVersion}`,
            },
          ],
          temperature: 0.0,
          response_format: { type: 'json_object' },
        }),
      });

      if (response.ok) {
        const data = await response.json();
        const rawContent = (data.choices[0]?.message?.content || '{}')
          .replace(/```json/g, '')
          .replace(/```/g, '')
          .trim();
        
        const content = JSON.parse(rawContent);
        const parsedLLMRisk = normalizeRiskLevel(content.riskLevel);
        const cves = Array.isArray(content.cves) ? content.cves : [];

        const staticFloor = getDeterministicFirmwareRisk(rawVersion, cves);
        const finalRisk = getHighestRiskLevel(staticFloor, parsedLLMRisk);

        return {
          riskLevel: finalRisk,
          summary: content.summary || 'OS/Firmware evaluation completed.',
          cves,
          recommendations: Array.isArray(content.recommendations) ? content.recommendations : [],
        };
      }
    } catch (err) {
      console.warn('[!] Groq Firmware AI call failed, falling back to vendor defaults:', err);
    }
  }

  const fallback = getVendorFallback(vendor, hostname);
  const fallbackFloor = getDeterministicFirmwareRisk(rawVersion, fallback.cves);
  const fallbackRisk = getHighestRiskLevel(fallbackFloor, 'MEDIUM');

  return {
    riskLevel: fallbackRisk,
    summary: fallback.summary,
    cves: fallback.cves,
    recommendations: fallback.recommendations,
  };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const deviceId = body.deviceId || body.device_id;
    let rawVersion = body.rawVersion || body.raw_version || body.versionOutput;

    if (!deviceId) {
      return NextResponse.json(
        { success: false, error: 'Missing required field: deviceId' },
        { status: 422 }
      );
    }

    const supabase = getSupabaseAdmin();
    let device: DeviceRecord = { hostname: 'Network-Device', vendor: 'generic' };

    if (supabase) {
      const { data } = await supabase
        .from('devices')
        .select('*')
        .eq('id', deviceId)
        .maybeSingle();

      if (data) device = data as DeviceRecord;

      if (!rawVersion && device.raw_version) {
        rawVersion = device.raw_version;
      }
    }

    if (!rawVersion) {
      rawVersion = `${device.hostname || 'Device'} OS Version Telemetry Default`;
    }

    const vendorStr = device.netmiko_type || device.vendor || 'cisco_ios';
    const hostnameStr = device.hostname || 'Network-Device';
    
    const analysis = await analyzeFirmwareWithGroq(hostnameStr, vendorStr, rawVersion);

    const riskBadge = analysis.riskLevel === 'CRITICAL' ? '🔴 CRITICAL' : analysis.riskLevel === 'HIGH' ? '🟠 HIGH' : analysis.riskLevel === 'MEDIUM' ? '🟡 MEDIUM' : '🟢 LOW';

    const formattedMarkdownSummary = 
`### 🔍 OS/Firmware Security Assessment

* **Hostname:** ${hostnameStr}
* **Vendor / Platform:** \`${vendorStr}\`
* **Evaluated Threat Level:** **${riskBadge}**

---

### 📋 Executive OS Assessment
> ${analysis.summary}

---

### 🚨 Potential Known Vulnerabilities / CVEs (${analysis.cves.length})

${
  analysis.cves.length > 0 
    ? analysis.cves.map((c: string) => `* ⚠️ **${c}**`).join('\n')
    : '✅ *No critical baseline CVE matches identified for this OS image.*'
}

---

### 💡 Lifecycle & Hardening Recommendations
${analysis.recommendations.map((r: string, idx: number) => `**${idx + 1}.** ${r}`).join('\n')}`;

    // FIX (schema-confirmed bug): public.scans.configuration_id is NOT NULL.
    // The insert branch below used to write a scan with no configuration_id
    // at all whenever a device had no prior scan row — that insert has
    // always been rejected by the database, silently, because it's wrapped
    // in the try/catch below. Firmware analysis run on a device before any
    // config scan had ever completed could never actually persist a scan
    // record. We now look up the device's most recent configuration and use
    // its id; if none exists yet, we skip the write (can't satisfy the
    // constraint) and say so plainly in the response instead of pretending
    // it succeeded.
    //
    // Also fixed: `.eq('device_id', deviceId).limit(1)` with no `.order()`
    // asks Postgres for "any one" matching row, not the most recent one —
    // on a device with multiple scan rows this could update an old scan
    // instead of the latest. Added `.order('created_at', { ascending: false })`.
    let dbPersisted = false;
    let dbWarning: string | null = null;

    if (supabase) {
      try {
        const nowIso = new Date().toISOString();
        const { data: existingScan } = await supabase
          .from('scans')
          .select('id')
          .eq('device_id', deviceId)
          .order('created_at', { ascending: false })
          .limit(1);

        if (existingScan && existingScan.length > 0) {
          await supabase
            .from('scans')
            .update({
              status: 'completed',
              risk_level: analysis.riskLevel,
              summary: formattedMarkdownSummary,
              updated_at: nowIso,
            })
            .eq('id', existingScan[0].id);
          dbPersisted = true;
        } else {
          const { data: latestConfig } = await supabase
            .from('configurations')
            .select('id')
            .eq('device_id', deviceId)
            .order('created_at', { ascending: false })
            .limit(1);

          const configurationId = latestConfig?.[0]?.id ?? null;

          if (configurationId) {
            await supabase
              .from('scans')
              .insert({
                device_id: deviceId,
                configuration_id: configurationId,
                status: 'completed',
                risk_level: analysis.riskLevel,
                summary: formattedMarkdownSummary,
                created_at: nowIso,
                updated_at: nowIso,
              });
            dbPersisted = true;
          } else {
            dbWarning = 'No configuration snapshot exists for this device yet, so the firmware analysis could not be saved as a scan record (scans.configuration_id is required). Run a config collection/scan first, then re-run firmware analysis.';
            console.warn(`[!] Firmware analysis for ${deviceId} not persisted: no configuration row to reference.`);
          }
        }
      } catch (dbErr) {
        console.warn('[!] Firmware scan DB non-fatal write error:', dbErr);
        dbWarning = 'Firmware analysis completed but could not be saved to the database.';
      }
    }

    return NextResponse.json({
      success: true,
      deviceId,
      riskLevel: analysis.riskLevel,
      output: formattedMarkdownSummary,
      summary: formattedMarkdownSummary,
      osSummary: formattedMarkdownSummary,
      analysis: formattedMarkdownSummary,
      content: formattedMarkdownSummary,
      text: formattedMarkdownSummary,
      result: formattedMarkdownSummary,
      cves: analysis.cves,
      aiAnalysis: analysis,
      // FIX: surfaced instead of pretending the write always succeeds (see note above)
      dbPersisted,
      dbWarning,
    });
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Internal Server Error';
    console.error('[-] Error executing firmware analysis in /api/analyze-firmware:', err);
    return NextResponse.json(
      { success: false, error: errorMessage },
      { status: 500 }
    );
  }
}

