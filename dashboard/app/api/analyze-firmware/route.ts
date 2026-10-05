// dashboard/app/api/analyze-firmware/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';
// FIX: this route used to run its own ad-hoc vendor detection
// (`vendor.toLowerCase().includes('cisco')` etc.) completely separately from
// the real detectVendor() in cisBenchmarks.ts. Two parallel, independently
// maintained vendor-classification implementations WILL drift apart — e.g.
// cisBenchmarks.ts treats "comware"/"hp" as aruba_hpe, this file didn't know
// that vendor existed at all. Now both files agree on vendor classification
// by construction, because there's only one implementation.
import { detectVendor, VendorType } from '@/lib/cisBenchmarks';

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
  // FIX (Fix C): now carries each verified CVE's real NVD description
  // alongside its id, instead of just the bare id string, so the UI can
  // show ground-truth impact text rather than only the AI's own narrative.
  cves: VerifiedCve[];
  recommendations: string[];
  // NEW: previously these two values were never produced by the AI at all —
  // they were hardcoded three layers downstream (useDashboard.ts's
  // fetchScanResults/handleAnalyzeFirmware, then VersionTab.tsx's
  // deriveFirmwareMetrics vendor-guess table). The LLM now returns them
  // directly, same as it already does for cves/recommendations.
  targetFirmware: string;
  eolStatus: string;
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

// FIX (TS2345): this only ever reads cves.length, never an element's
// shape, so it doesn't need to care whether it's called with the old
// string[] (offline vendor fallback) or the new VerifiedCve[] (live Groq
// path, see Fix C) — widened to `{ length: number }` so both call sites
// type-check without needing two near-duplicate functions.
function getDeterministicFirmwareRisk(rawVersion: string, cves: { length: number } = []): RiskLevel {
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

// FIX (real bug, confirmed by hand, round 2): the previous verification pass
// only checked "does this CVE ID exist in NVD at all" — it never checked
// whether the CVE actually applies to the PRODUCT being audited. On a real
// run against a Catalyst 9300 (IOS-XE 17.9.5), the model returned
// CVE-2023-20187 (Cisco ASR 1000 routers, L2TP/mLRE DoS — a completely
// different hardware family) and CVE-2023-20188 / CVE-2023-20189 (Cisco
// Small Business 200/300/500 series switches' web UI — not Catalyst, not
// IOS-XE at all). All three are real, NVD-confirmed CVE IDs, so the old
// existence-only check passed every one of them through. The model is
// recalling genuine Cisco CVE numbers and misattributing them to the wrong
// product line — a subtler version of the same hallucination pattern.
//
// NVD's CVE 2.0 API response includes `configurations[].nodes[].cpeMatch[]`,
// the actual list of CPE strings (vendor:product:version) the CVE is
// recorded against. We now also require that at least one cpeMatch
// criteria string in the response contains a platform keyword for the
// vendor we detected locally (see VENDOR_CPE_HINTS) — if NONE of the CVE's
// recorded CPEs mention this platform family at all, it's dropped as a
// platform mismatch, independent of whether the ID itself is real.
//
// Still fails OPEN when the data needed to judge is simply missing or
// unreachable (no configurations block on an older/sparse CVE record, or a
// network/timeout error) — that's "can't confirm," not "confirmed wrong."
// Only a confirmed NVD 404 (doesn't exist) or a confirmed CPE mismatch
// (exists, but for a different product) causes a drop.
const VENDOR_CPE_HINTS: Record<VendorType, string[]> = {
  // FIX (real bug, confirmed by hand, round 3): the bare 'ios' hint matched
  // ANY cpe string containing that substring — including "ios_xr_software"
  // and "ios_xe_software". That's exactly how CVE-2023-20190 slipped
  // through: it's an IOS-XR-only "incorrect authorization" vulnerability
  // (CVSS 5.3), but its CPE string "cpe:...:cisco:ios_xr_software:..."
  // contains the substring "ios", so it matched cisco_ios's hint list and
  // was kept instead of dropped. Anchored to ':ios:' (colon-delimited)
  // instead, which only matches the exact classic-IOS product field, not
  // "ios_xr_software" or "ios_xe_software" as substrings of something else.
  cisco_ios: ['ios_xe', ':ios:', 'catalyst'],
  cisco_nxos: ['nx-os', 'nxos', 'nexus'],
  cisco_xr: ['ios_xr', 'ios-xr'],
  juniper: ['junos'],
  arista: ['eos', 'arista'],
  fortinet: ['fortios', 'fortigate'],
  paloalto: ['pan-os', 'panos', 'paloaltonetworks'],
  huawei: ['vrp', 'huawei'],
  aruba_hpe: ['arubaos', 'procurve', 'aruba'],
  dell_os10: ['os10', 'dell'],
  f5_tmsh: ['big-ip', 'bigip', 'tmos', 'f5'],
  nokia_sros: ['sr_os', 'timos', 'nokia'],
  vyos: ['vyos'],
  extreme_exos: ['exos', 'extreme'],
  mikrotik: ['routeros', 'mikrotik'],
  // No reliable platform keyword to check against for an unidentified
  // vendor — nothing to confirm OR deny, so this vendor is exempted from
  // the CPE check entirely (existence-only verification still applies).
  generic: [],
};

// FIX (Fix B, accepted as a heuristic mitigation, not a complete fix):
// NVD's structured CPE data for a CVE often only encodes the SOFTWARE
// family (e.g. cisco:ios_xe_software), not which HARDWARE line it
// affects. A CVE that only affects ASR/ISR routers running IOS-XE can
// still pass the CPE platform check above for a Catalyst switch also
// running IOS-XE, because NVD's own structured data doesn't distinguish
// hardware lines — that part is a genuine data gap, not something more
// code alone can fully close.
//
// What IS fixable: NVD's free-text description for a CVE usually DOES
// name the specific hardware line in prose (e.g. "Cisco ASR 1000 Series
// Aggregation Services Routers"). So this cross-checks that description
// text against the device's own detected hardware family (read from its
// real "show version" output) and drops the CVE if the description
// explicitly names a DIFFERENT family and never mentions the device's
// own family. Built per-vendor, multi-vendor-safe: a vendor with no
// entry here (or an unidentified device family) is exempted entirely —
// same fail-open philosophy as VENDOR_CPE_HINTS above, and no vendor is
// special-cased in the code path itself.
const VENDOR_HARDWARE_FAMILIES: Partial<Record<VendorType, string[][]>> = {
  cisco_ios: [
    ['catalyst'],
    ['asr'],
    ['isr', 'integrated services router'],
    ['small business', 'sf200', 'sg200', 'sf300', 'sg300', 'sf500', 'sg500', 'rv1', 'rv2', 'rv3'],
    ['nexus'],
  ],
  // Other vendors aren't yet a confirmed instance of this exact failure
  // mode in testing. Left unset (safe no-op) rather than guessed at —
  // add an entry here only once a real same-OS-different-hardware case
  // is observed for that vendor, the same way this one was.
};

/** Finds which hardware-family bucket a device's own version text matches, or -1 if none. */
function detectHardwareFamily(rawVersionText: string, families: string[][]): number {
  const lower = (rawVersionText || '').toLowerCase();
  for (let i = 0; i < families.length; i++) {
    if (families[i].some((kw) => lower.includes(kw))) return i;
  }
  return -1;
}

// FIX (Fix C): previously only the CVE *ID* survived verification — the
// AI's own plain-English narrative of each CVE's impact (in its
// `summary`) was never checked against anything, so a real,
// platform-correct CVE ID could still carry an exaggerated description
// (e.g. calling a command-authorization-bypass "remote code execution")
// with nothing to catch it. NVD's own `descriptions[].value` text is
// already being fetched during the existence check below — this now
// keeps it and returns it alongside each verified CVE, so the UI can
// show the real, verified NVD description directly instead of relying
// solely on the AI's unverified narrative.
export interface VerifiedCve {
  id: string;
  nvdDescription: string | null;
}

async function verifyCvesAgainstNvd(
  candidates: string[],
  vendorType: VendorType,
  deviceRawVersion: string
): Promise<VerifiedCve[]> {
  const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;
  const syntacticallyValid = Array.from(
    new Set(
      candidates
        .map((c) => String(c || '').trim().toUpperCase())
        .filter((c) => CVE_RE.test(c))
    )
  );

  // Hard cap: this checks against a third-party API with no key (NVD's
  // public rate limit is ~5 requests/30s), not a bulk import job. A single
  // firmware analysis realistically surfaces a handful of CVEs — if the
  // model ever returns more than this, something else is already wrong
  // with that response and isn't worth burning the rate limit on.
  const toCheck = syntacticallyValid.slice(0, 8);
  const verified: VerifiedCve[] = [];
  const platformHints = VENDOR_CPE_HINTS[vendorType] || [];

  for (const cveId of toCheck) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
        { signal: controller.signal }
      ).finally(() => clearTimeout(timeoutId));

      if (res.status === 404) {
        console.warn(`[!] Dropping unverifiable CVE from AI output (NVD 404): ${cveId}`);
        continue;
      }
      if (!res.ok) {
        // Rate-limited or NVD-side error — can't confirm either way, so
        // don't penalize the candidate for an availability problem. No
        // real description available either, since the fetch itself failed.
        verified.push({ id: cveId, nvdDescription: null });
        continue;
      }
      const data = await res.json();
      const record = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities[0] : null;
      if (!record) {
        console.warn(`[!] Dropping unverifiable CVE from AI output (no NVD record): ${cveId}`);
        continue;
      }

      // Fix C: pull NVD's own real description once, reused below both
      // for the hardware-family check and as the verified return value —
      // this is what the UI should show instead of trusting the AI's own
      // unverified narrative about this CVE's impact.
      const nvdDescriptions = record?.cve?.descriptions;
      const nvdDescription: string | null = Array.isArray(nvdDescriptions)
        ? (nvdDescriptions.find((d: any) => d?.lang === 'en')?.value || null)
        : null;

      // Platform relevance check (see doc comment above). Walk every
      // cpeMatch criteria string in every config node and require at least
      // one to mention this vendor's platform family.
      if (platformHints.length > 0) {
        const configurations = record?.cve?.configurations;
        const cpeStrings: string[] = [];
        if (Array.isArray(configurations)) {
          for (const config of configurations) {
            for (const node of config?.nodes || []) {
              for (const match of node?.cpeMatch || []) {
                if (typeof match?.criteria === 'string') cpeStrings.push(match.criteria.toLowerCase());
              }
            }
          }
        }

        if (cpeStrings.length > 0) {
          const matchesPlatform = cpeStrings.some((cpe) => platformHints.some((hint) => cpe.includes(hint)));
          if (!matchesPlatform) {
            console.warn(`[!] Dropping ${cveId} as a platform mismatch for ${vendorType} — CPE data: ${cpeStrings.slice(0, 3).join(', ')}`);
            continue;
          }
        }
        // No cpeMatch data at all on this record — can't confirm OR deny
        // relevance, so fail open rather than punish a sparse/older CVE
        // entry for missing metadata it never had.
      }

      // Fix B: hardware-family cross-check against the CVE's own
      // free-text description (see doc comment above verifyCvesAgainstNvd).
      const hwFamilies = VENDOR_HARDWARE_FAMILIES[vendorType];
      if (hwFamilies && hwFamilies.length > 0) {
        const deviceFamilyIdx = detectHardwareFamily(deviceRawVersion, hwFamilies);
        if (deviceFamilyIdx !== -1 && nvdDescription) {
          const descLower = nvdDescription.toLowerCase();
          const namesOwnFamily = hwFamilies[deviceFamilyIdx].some((kw) => descLower.includes(kw));
          const namesOtherFamily = hwFamilies.some(
            (fam, idx) => idx !== deviceFamilyIdx && fam.some((kw) => descLower.includes(kw))
          );
          if (namesOtherFamily && !namesOwnFamily) {
            console.warn(
              `[!] Dropping ${cveId} as a hardware-family mismatch for ${vendorType} — NVD description names a different hardware line than this device. Excerpt: ${nvdDescription.slice(0, 150)}`
            );
            continue;
          }
        }
        // Either no usable description text, it's silent on hardware
        // family either way, or the device's own family couldn't be
        // identified from its version text — can't confirm OR deny, so
        // fail open rather than guessing.
      }

      verified.push({ id: cveId, nvdDescription });
    } catch (err) {
      // Network/timeout failure — fail open, see doc comment above. No
      // description available since the fetch itself never completed.
      console.warn(`[!] NVD verification unreachable for ${cveId}, keeping candidate as unconfirmed:`, err);
      verified.push({ id: cveId, nvdDescription: null });
    }
  }

  return verified;
}

interface VendorFallbackEntry {
  cves: string[];
  recommendations: string[];
  summary: string;
  targetFirmware: string;
  eolStatus: string;
}

// FIX: this used to only cover cisco/dell/aruba, with everything else —
// including fortinet, despite fortinet having full CIS rule coverage in
// cisBenchmarks.ts — silently landing on one generic bucket. The whole
// system is built as multi-vendor (see VendorType in cisBenchmarks.ts);
// this fallback table now matches that same vendor list 1:1. This is ONLY
// the offline/last-resort safety net used when Groq is unreachable or
// returns nothing usable — the LLM call above it is still the primary
// source of truth per-device.
const VENDOR_FALLBACK_MATRIX: Record<VendorType, (hostname: string) => VendorFallbackEntry> = {
  cisco_ios: (h) => ({
    cves: ['CVE-2023-20198', 'CVE-2023-20273'],
    recommendations: [
      'Enforce SSHv2 protocol and restrict line vty access lists.',
      'Upgrade IOS-XE release to latest active maintenance train.',
      'Disable HTTP/HTTPS integrated web server if unused.',
    ],
    summary: `Firmware analysis completed for ${h} (Cisco IOS). OS version detected; verify active web UI configuration and management ACLs.`,
    targetFirmware: 'Cisco IOS-XE 17.09.05 LTS',
    eolStatus: 'Active / Supported',
  }),
  cisco_nxos: (h) => ({
    cves: ['CVE-2023-20123'],
    recommendations: [
      'Upgrade NX-OS to the latest recommended maintenance release for this platform.',
      'Disable legacy Telnet/HTTP management features (feature telnet / feature http-server).',
      'Restrict management-plane access via a dedicated mgmt0 VRF and ACL.',
    ],
    summary: `Firmware analysis completed for ${h} (Cisco NX-OS). Verify current release against Cisco's NX-OS security advisories.`,
    targetFirmware: 'Cisco NX-OS 10.3(x) LTS',
    eolStatus: 'Active / Supported',
  }),
  cisco_xr: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade IOS-XR to the latest recommended maintenance release for this platform.',
      'Restrict management plane protection (MPP) to trusted interfaces only.',
      'Disable unused XML/NETCONF agents if not actively used for automation.',
    ],
    summary: `Firmware analysis completed for ${h} (Cisco IOS-XR). Verify current release against Cisco's IOS-XR security advisories.`,
    targetFirmware: 'Cisco IOS-XR 7.9.x LTS',
    eolStatus: 'Active / Supported',
  }),
  juniper: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade Junos to the latest recommended EEOL (Extended End-of-Life) release train.',
      'Disable Telnet services and enforce SSH-only system services.',
      'Enable login password format sha-512 for all local accounts.',
    ],
    summary: `Firmware analysis completed for ${h} (Juniper Junos). Verify current release against Juniper's published EEOL schedule.`,
    targetFirmware: 'Junos 21.4 EEOL',
    eolStatus: 'Active / Supported',
  }),
  arista: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade EOS to the latest recommended release in Arista\'s current release train.',
      'Disable the HTTP management API protocol, keep HTTPS only.',
      'Enforce AAA authentication via TACACS+/RADIUS rather than local-only accounts.',
    ],
    summary: `Firmware analysis completed for ${h} (Arista EOS). Verify current release against Arista's security advisories.`,
    targetFirmware: 'Arista EOS 4.31.x',
    eolStatus: 'Active / Supported',
  }),
  fortinet: (h) => ({
    cves: ['CVE-2022-40684'],
    recommendations: [
      'Upgrade FortiOS to the latest patched release in the current support train.',
      'Restrict SSL-VPN and management-GUI exposure to trusted source IPs only.',
      'Enable two-factor authentication for all administrative accounts.',
    ],
    summary: `Firmware analysis completed for ${h} (Fortinet FortiOS). Verify current build against Fortinet PSIRT advisories, particularly SSL-VPN CVEs.`,
    targetFirmware: 'FortiOS 7.4.x LTS',
    eolStatus: 'Active / Supported',
  }),
  paloalto: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade PAN-OS to the latest preferred release per Palo Alto\'s release recommendation.',
      'Disable Telnet/HTTP management services (disable-telnet / disable-http).',
      'Enforce a dedicated authentication profile for all administrative accounts.',
    ],
    summary: `Firmware analysis completed for ${h} (Palo Alto PAN-OS). Verify current release against Palo Alto's PSIRT advisories.`,
    targetFirmware: 'PAN-OS 11.1.x',
    eolStatus: 'Active / Supported',
  }),
  huawei: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade VRP to the latest recommended patch version for this platform.',
      'Disable the Telnet server (undo telnet server enable) and enforce SSH/Stelnet.',
      'Configure a dedicated AAA authentication scheme rather than local-only auth.',
    ],
    summary: `Firmware analysis completed for ${h} (Huawei VRP). Verify current version against Huawei's security advisories.`,
    targetFirmware: 'Huawei VRP 8.x (current maintenance release)',
    eolStatus: 'Active / Supported',
  }),
  aruba_hpe: (h) => ({
    cves: ['CVE-2023-35984'],
    recommendations: [
      'Migrate to recommended ArubaOS-CX LTS release train.',
      'Disable cleartext REST API management services on default VRF.',
      'Verify AAA RADIUS server failover configuration for local user accounts.',
    ],
    summary: `Firmware audit complete for ${h} (ArubaOS-CX). System version identified; review vendor portal for platform release updates.`,
    targetFirmware: 'ArubaOS-CX 10.13.1000 LTS',
    eolStatus: 'Active / Supported',
  }),
  dell_os10: (h) => ({
    cves: ['CVE-2022-2917'],
    recommendations: [
      'Upgrade OS10 image to the latest recommended LTS maintenance release.',
      'Ensure RESTCONF/eAPI management endpoints enforce strict TLS 1.2+ encryption.',
      'Restrict control-plane administrative access via explicit management VRF policy.',
    ],
    summary: `Firmware analysis completed for target host ${h} running Dell OS10. System version identified; check Dell Security Advisories for baseline OS updates.`,
    targetFirmware: 'Dell OS10 10.5.6.0',
    eolStatus: 'Active / Supported',
  }),
  f5_tmsh: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade BIG-IP TMOS to the latest recommended point release for this version train.',
      'Verify sys sshd Protocol is restricted to SSHv2 only.',
      'Restrict the management interface to a dedicated out-of-band network.',
    ],
    summary: `Firmware analysis completed for ${h} (F5 BIG-IP / TMOS). Verify current version against F5's K-article security advisories.`,
    targetFirmware: 'F5 BIG-IP TMOS 17.1.x',
    eolStatus: 'Active / Supported',
  }),
  nokia_sros: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade SR OS to the latest recommended release for this chassis/platform.',
      'Disable Telnet (configure system security telnet shutdown) and enforce SSH only.',
      'Enable hash2 password storage for all local administrative accounts.',
    ],
    summary: `Firmware analysis completed for ${h} (Nokia SR OS). Verify current release against Nokia's security bulletins.`,
    targetFirmware: 'Nokia SR OS 23.x',
    eolStatus: 'Active / Supported',
  }),
  vyos: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade to the latest VyOS LTS rolling release.',
      'Remove the Telnet service entirely (delete service telnet) and keep SSH only.',
      'Configure RADIUS/TACACS+ authentication rather than local-only accounts.',
    ],
    summary: `Firmware analysis completed for ${h} (VyOS). Verify current version against the VyOS LTS release schedule.`,
    targetFirmware: 'VyOS 1.4 LTS',
    eolStatus: 'Active / Supported',
  }),
  extreme_exos: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade EXOS to the latest recommended release for this switch family.',
      'Disable Telnet and the web UI in favor of SSH-only management (disable telnet / disable web).',
      'Enable AAA (enable aaa) rather than relying on local accounts only.',
    ],
    summary: `Firmware analysis completed for ${h} (Extreme EXOS). Verify current version against Extreme Networks security advisories.`,
    targetFirmware: 'Extreme EXOS 32.x',
    eolStatus: 'Active / Supported',
  }),
  mikrotik: (h) => ({
    cves: [],
    recommendations: [
      'Upgrade RouterOS to the latest stable channel release.',
      'Disable the Telnet and www services (/ip service disable telnet,www), keep SSH/HTTPS only.',
      'Enable RADIUS-backed authentication for administrative users.',
    ],
    summary: `Firmware analysis completed for ${h} (MikroTik RouterOS). Verify current version against MikroTik's changelog for security fixes.`,
    targetFirmware: 'MikroTik RouterOS 7.x (stable channel)',
    eolStatus: 'Active / Supported',
  }),
  generic: (h) => ({
    cves: [],
    recommendations: [
      'Perform hardware life-cycle check with device manufacturer.',
      'Upgrade system software to current secure baseline release.',
      'Audit management interfaces for unencrypted transport protocols.',
    ],
    summary: `Firmware evaluation completed for host ${h}. Vendor platform could not be positively identified from the available telemetry — check manufacturer releases for active CVE hotfixes manually.`,
    targetFirmware: 'Unable to determine (unidentified platform)',
    eolStatus: 'Unknown — verify with vendor',
  }),
};

/**
 * Returns platform-specific default security advisories when Groq API is
 * offline, unreachable, or returns nothing usable. This is now the ONLY
 * place static vendor version/lifecycle guesses live, used strictly as an
 * offline fallback across ALL vendors this system supports (see
 * VendorType in cisBenchmarks.ts) — not just a handful. It is never the
 * primary source of targetFirmware/eolStatus when Groq is reachable; the
 * LLM is asked for those directly in analyzeFirmwareWithGroq below.
 */
function getVendorFallback(vendorType: VendorType, hostname: string): VendorFallbackEntry {
  return VENDOR_FALLBACK_MATRIX[vendorType](hostname);
}

async function analyzeFirmwareWithGroq(
  hostname: string,
  vendorType: VendorType,
  rawVersion: string
): Promise<FirmwareAnalysis> {
  const apiKey = process.env.GROQ_API_KEY;
  const fallback = getVendorFallback(vendorType, hostname);

  if (apiKey) {
    try {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'openai/gpt-oss-120b',
          messages: [
            {
              role: 'system',
              content:
                // FIX: the model was previously allowed to silently omit
                // targetFirmware/eolStatus (leaving them blank, which forced
                // this route to fall back to generic placeholder text even
                // on a fully successful call). It's now told explicitly
                // that these two fields are REQUIRED on every response, and
                // given exactly one sanctioned way to decline (only when the
                // platform truly cannot be identified at all) rather than
                // being able to leave them empty by default.
                'You are an expert network OS and firmware vulnerability auditor. Analyze the provided "show version" telemetry for OS version, known EOL/EOS status, and CVE security vulnerabilities SPECIFIC to the indicated vendor/OS platform. Return ONLY valid JSON with keys: riskLevel (CRITICAL|HIGH|MEDIUM|LOW), summary (string), cves (string array), recommendations (string array), targetFirmware (string), and eolStatus (string). ' +
                'targetFirmware and eolStatus are REQUIRED on every response — do not leave them blank or omit them. targetFirmware must name the vendor\'s current recommended/LTS stable release train for the EXACT platform identified (e.g. "Cisco IOS-XE 17.09.05 LTS", "FortiOS 7.4.x LTS"), based on real, current vendor lifecycle data for that platform. eolStatus must be either "Active / Supported" or "End-of-Life (EOL)", reflecting the DETECTED version\'s actual lifecycle status (not the recommended version\'s). ' +
                'The only acceptable reason to not give a specific targetFirmware is if the vendor/OS platform itself cannot be identified from the input at all — in that exact case only, return targetFirmware "Unable to determine (unidentified platform)" and eolStatus "Unknown — verify with vendor". Do NOT invent CVEs for unrelated hardware vendors. ' +
                // FIX (real bug, confirmed by hand): the model was returning
                // CVE IDs that do not exist for the evaluated platform —
                // e.g. CVE-2024-2005/2006/2007 for a Cisco IOS-XE 17.9.5
                // device, none of which are real Cisco CVEs (CVE-2024-2005
                // is not even a CVE — it's an unrelated Talos vulnerability
                // report ID). Every cves[] entry is now independently
                // verified against the NVD database after this call returns
                // (see verifyCvesAgainstNvd below), but the model is also
                // told directly not to guess, since prevention beats
                // filtering.
                'cves must only contain CVE identifiers you are genuinely confident are real, published vulnerabilities that apply to this exact vendor/platform AND hardware family and version range. Never invent a CVE ID, never approximate one, and never reuse an ID you loosely recall from a different product, a different vendor, or a non-CVE report (e.g. a Talos/PSIRT advisory number is NOT a CVE ID). ' +
                // FIX (round 2, real bug, confirmed by hand): the model also
                // returns CVE IDs that ARE real and ARE for Cisco, but for
                // the WRONG Cisco product line — e.g. attaching an ASR 1000
                // router CVE or a Small Business switch web-UI CVE to a
                // Catalyst 9300 running IOS-XE. Being a real Cisco CVE
                // number is not the same as applying to this exact
                // hardware family; the model must actively rule that out,
                // not just recall a plausible-looking ID.
                'Before including any CVE, explicitly confirm it is scoped to the SAME hardware family and software platform as the device under analysis (e.g. Catalyst switch + IOS-XE is a different affected-product scope than ASR/ISR routers, and different again from the Small Business 200/300/500 switch line, even though all three are "Cisco"). If you are not certain a specific CVE applies to BOTH this vendor/platform AND this exact hardware family, omit it entirely — returning an empty cves array is the correct, expected answer when you have no high-confidence match, not a failure to avoid.',
            },
            {
              role: 'user',
              content: `Device Context:\n- Hostname: ${hostname}\n- Vendor / OS Platform: ${vendorType}\n\nCLI Show Version Output:\n${rawVersion}`,
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
        const rawCves = Array.isArray(content.cves) ? content.cves : [];
        // FIX: verify every candidate CVE against NVD — both that it exists
        // AND that its recorded CPE data actually names this platform
        // family — before trusting it. See verifyCvesAgainstNvd doc
        // comment above for why both checks are needed.
        const cves = await verifyCvesAgainstNvd(rawCves, vendorType, rawVersion);

        const staticFloor = getDeterministicFirmwareRisk(rawVersion, cves);
        const finalRisk = getHighestRiskLevel(staticFloor, parsedLLMRisk);

        return {
          riskLevel: finalRisk,
          summary: content.summary || 'OS/Firmware evaluation completed.',
          cves,
          recommendations: Array.isArray(content.recommendations) ? content.recommendations : [],
          // Trust the LLM's answer when it gave one; only fall back to the
          // vendor-specific static guess for whichever field (if any) it
          // still left blank despite the stricter prompt above.
          targetFirmware:
            typeof content.targetFirmware === 'string' && content.targetFirmware.trim()
              ? content.targetFirmware.trim()
              : fallback.targetFirmware,
          eolStatus:
            typeof content.eolStatus === 'string' && content.eolStatus.trim()
              ? content.eolStatus.trim()
              : fallback.eolStatus,
        };
      } else {
        // FIX: a non-OK response (401 bad/missing key, 429 rate-limited,
        // 400 bad request, 5xx Groq-side error) was previously swallowed
        // completely silently — no console output at all, nothing to tell
        // you WHY it fell back to the generic vendor placeholder. This was
        // indistinguishable from "working as intended" in the logs.
        const errBody = await response.text().catch(() => '<unreadable body>');
        console.warn(
          `[!] Groq Firmware AI call returned non-OK status ${response.status} ${response.statusText}. Falling back to vendor defaults. Body: ${errBody.slice(0, 500)}`
        );
      }
    } catch (err) {
      console.warn('[!] Groq Firmware AI call failed, falling back to vendor defaults:', err);
    }
  }

  const fallbackFloor = getDeterministicFirmwareRisk(rawVersion, fallback.cves);
  const fallbackRisk = getHighestRiskLevel(fallbackFloor, 'MEDIUM');

  return {
    riskLevel: fallbackRisk,
    summary: fallback.summary,
    // Offline/static fallback entries are fixed, known-good CVE IDs we
    // wrote by hand (not AI output), but they still weren't looked up
    // against NVD at request time, so there's no live description to
    // attach here — nvdDescription is null rather than fabricated.
    cves: fallback.cves.map((id) => ({ id, nvdDescription: null })),
    recommendations: fallback.recommendations,
    targetFirmware: fallback.targetFirmware,
    eolStatus: fallback.eolStatus,
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

    // FIX: was `device.netmiko_type || device.vendor || 'cisco_ios'` passed
    // as a raw string straight to the Groq prompt and to getVendorFallback's
    // own separate `.includes()` checks. Now resolved once, the same way
    // cisBenchmarks.ts resolves it for the config-audit engine, so a device
    // classified as e.g. aruba_hpe there is never silently treated as
    // "generic" here.
    const vendorInputStr = body.vendor || device.netmiko_type || device.vendor || 'cisco_ios';
    const vendorType: VendorType = detectVendor(vendorInputStr);
    const hostnameStr = device.hostname || 'Network-Device';

    const analysis = await analyzeFirmwareWithGroq(hostnameStr, vendorType, rawVersion);

    const riskBadge = analysis.riskLevel === 'CRITICAL' ? '🔴 CRITICAL' : analysis.riskLevel === 'HIGH' ? '🟠 HIGH' : analysis.riskLevel === 'MEDIUM' ? '🟡 MEDIUM' : '🟢 LOW';

    const formattedMarkdownSummary =
`### 🔍 OS/Firmware Security Assessment

* **Hostname:** ${hostnameStr}
* **Vendor / Platform:** \`${vendorType}\`
* **Evaluated Threat Level:** **${riskBadge}**
* **Recommended LTS Release:** ${analysis.targetFirmware}
* **Lifecycle Support Status:** ${analysis.eolStatus}

---

### 📋 Executive OS Assessment
> ${analysis.summary}

---

### 🚨 Potential Known Vulnerabilities / CVEs (${analysis.cves.length})

${
  analysis.cves.length > 0
    // FIX (Fix C): show NVD's own verified description under each CVE
    // instead of only the AI's unverified narrative claim about it — this
    // is the actual ground-truth text, not a paraphrase.
    ? analysis.cves
        .map((c) => `* ⚠️ **${c.id}** — ${c.nvdDescription || '_No NVD description available for this CVE (lookup failed or record is sparse); verify manually before treating as confirmed impact._'}`)
        .join('\n')
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
    //
    // NEW: both the update and insert payloads below now also persist
    // target_firmware/eol_status, so the AI-derived values survive a page
    // refresh instead of fetchScanResults() hardcoding placeholder strings
    // over them (see the matching fix in useDashboard.ts).
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
              target_firmware: analysis.targetFirmware,
              eol_status: analysis.eolStatus,
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
                target_firmware: analysis.targetFirmware,
                eol_status: analysis.eolStatus,
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
      // FIX: kept as plain string[] for backward compatibility with
      // whatever already reads data.cves (e.g. VersionTab.tsx) expecting
      // bare CVE ID strings — changing this shape without seeing that
      // file's current code could silently break its rendering (a mapped
      // object would show as "[object Object]"). The new verified
      // descriptions (Fix C) are additive, in cveDetails below.
      cves: analysis.cves.map((c) => c.id),
      // NEW (Fix C): each verified CVE's real NVD description alongside
      // its id — use this in the UI instead of cves[] wherever you want
      // to show ground-truth impact text rather than just the bare ID.
      cveDetails: analysis.cves,
      aiAnalysis: analysis,
      // NEW: these two are what useDashboard.ts's handleAnalyzeFirmware()
      // was already trying to read (data.targetFirmware / data.eolStatus) —
      // it just never received them before now.
      targetFirmware: analysis.targetFirmware,
      eolStatus: analysis.eolStatus,
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