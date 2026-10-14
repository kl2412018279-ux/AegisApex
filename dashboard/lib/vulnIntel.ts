// dashboard/lib/vulnIntel.ts
// Vulnerability intelligence for firmware analysis.
//
//   1. Deterministic CVE lookup: parse the platform + version out of
//      "show version", build a CPE 2.3 name, and ask NVD for every CVE whose
//      affected-version ranges include it. This finds CVEs the AI never
//      mentions, which the old "AI suggests, NVD verifies" flow could not.
//   2. AI-suggested CVEs are still accepted, but only after NVD confirms
//      they exist and apply to this platform and hardware family.
//   3. Every CVE is enriched with CISA KEV (actively exploited) and FIRST
//      EPSS (probability of exploitation in the next 30 days).
//   4. Optional: Cisco PSIRT openVuln advisories when API credentials exist.
import type { VendorType } from './cisBenchmarks';
import type { RiskLevel } from './risk';

const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_API = 'https://api.first.org/data/v1/epss';

export interface CveRecord {
  id: string;
  description: string | null;
  cvssScore: number | null;
  cvssSeverity: string | null;
  published: string | null;
  sources: Array<'nvd-cpe' | 'ai-verified' | 'cisco-psirt'>;
  advisoryUrl?: string | null;
  kev: boolean;
  kevDateAdded?: string | null;
  kevDueDate?: string | null;
  kevRansomware?: boolean;
  epss: number | null;
  epssPercentile: number | null;
}

export interface ParsedPlatform {
  part: 'o' | 'a';
  cpeVendor: string;
  cpeProduct: string;
  version: string;
  update: string | null;
  label: string;
}

export interface VulnLookupResult {
  platform: ParsedPlatform | null;
  cpe: string | null;
  cves: CveRecord[];
  totalMatched: number;
  sourcesQueried: string[];
  errors: string[];
}

// ─── Platform / version parsing ─────────────────────────────────────────────

/** "17.09.05" -> "17.9.5", "17.09.04a" -> "17.9.4a" (NVD does not zero-pad). */
export function stripZeroPadding(version: string): string {
  return version
    .split('.')
    .map((part) => part.replace(/^0+(?=\d)/, ''))
    .join('.');
}

export function parsePlatformVersion(vendor: VendorType, rawVersion: string): ParsedPlatform | null {
  const text = rawVersion || '';
  const m = (re: RegExp) => text.match(re);

  switch (vendor) {
    case 'cisco_ios': {
      const isXe = /ios[\s-]?xe|IOSXE|cat9k|catalyst l3 switch software/i.test(text);
      const v = m(/Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+[a-z]?|\([0-9a-z]+\)[0-9a-z]*))/i);
      if (!v) return null;
      if (isXe && /^\d+\.\d+\.\d+/.test(v[1])) {
        return { part: 'o', cpeVendor: 'cisco', cpeProduct: 'ios_xe', version: stripZeroPadding(v[1]).toLowerCase(), update: null, label: 'Cisco IOS XE' };
      }
      return { part: 'o', cpeVendor: 'cisco', cpeProduct: 'ios', version: v[1].toLowerCase(), update: null, label: 'Cisco IOS' };
    }
    case 'cisco_nxos': {
      const v = m(/(?:NXOS|system|kickstart):\s+version\s+([0-9]+\.[0-9]+\([0-9a-z.]+\)[0-9a-z]*)/i) || m(/version\s+([0-9]+\.[0-9]+\([0-9a-z.]+\))/i);
      return v ? { part: 'o', cpeVendor: 'cisco', cpeProduct: 'nx-os', version: v[1].toLowerCase(), update: null, label: 'Cisco NX-OS' } : null;
    }
    case 'cisco_xr': {
      const v = m(/Version\s+([0-9]+\.[0-9]+\.[0-9]+)/i);
      return v ? { part: 'o', cpeVendor: 'cisco', cpeProduct: 'ios_xr', version: v[1], update: null, label: 'Cisco IOS XR' } : null;
    }
    case 'juniper': {
      const v = m(/Junos:?\s*([0-9]+\.[0-9]+)(R[0-9]+(?:-S[0-9]+)?)?/i);
      return v ? { part: 'o', cpeVendor: 'juniper', cpeProduct: 'junos', version: v[1], update: v[2] ? v[2].toLowerCase() : null, label: 'Juniper Junos' } : null;
    }
    case 'arista': {
      const v = m(/Software image version:\s*([0-9]+\.[0-9]+\.[0-9]+[A-Z]?)/i);
      return v ? { part: 'o', cpeVendor: 'arista', cpeProduct: 'eos', version: v[1].toLowerCase(), update: null, label: 'Arista EOS' } : null;
    }
    case 'fortinet': {
      const v = m(/v([0-9]+\.[0-9]+\.[0-9]+)\s*,?\s*build/i) || m(/FortiOS\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i);
      return v ? { part: 'o', cpeVendor: 'fortinet', cpeProduct: 'fortios', version: v[1], update: null, label: 'Fortinet FortiOS' } : null;
    }
    case 'paloalto': {
      const v = m(/sw-version:\s*([0-9]+\.[0-9]+\.[0-9]+)(?:-(h[0-9]+))?/i);
      return v ? { part: 'o', cpeVendor: 'paloaltonetworks', cpeProduct: 'pan-os', version: v[1], update: v[2] ? v[2].toLowerCase() : null, label: 'Palo Alto PAN-OS' } : null;
    }
    case 'mikrotik': {
      const v = m(/version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
      return v ? { part: 'o', cpeVendor: 'mikrotik', cpeProduct: 'routeros', version: v[1], update: null, label: 'MikroTik RouterOS' } : null;
    }
    case 'extreme_exos': {
      const v = m(/ExtremeXOS\s+version\s+([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
      return v ? { part: 'o', cpeVendor: 'extremenetworks', cpeProduct: 'exos', version: v[1], update: null, label: 'Extreme EXOS' } : null;
    }
    case 'f5_tmsh': {
      const v = m(/Version\s+([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
      return v ? { part: 'a', cpeVendor: 'f5', cpeProduct: 'big-ip_local_traffic_manager', version: v[1], update: null, label: 'F5 BIG-IP LTM' } : null;
    }
    default:
      // Huawei VRP, Dell OS10, Nokia SR OS, VyOS, Aruba: NVD's CPE naming for
      // these is too inconsistent to query reliably. They fall back to the
      // AI-suggested, NVD-verified path only.
      return null;
  }
}

/** CPE 2.3 strings escape a handful of punctuation characters inside fields. */
function cpeEscape(value: string): string {
  return value.replace(/([()!"#$%&'+,/:;<=>@[\]^`{|}~])/g, '\\$1');
}

export function buildCpe(p: ParsedPlatform): string {
  return `cpe:2.3:${p.part}:${p.cpeVendor}:${p.cpeProduct}:${cpeEscape(p.version)}:${p.update ? cpeEscape(p.update) : '*'}`;
}

// ─── NVD ────────────────────────────────────────────────────────────────────

function nvdHeaders(): Record<string, string> {
  return process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
}

async function fetchWithTimeout(fetchImpl: typeof fetch, url: string, init: RequestInit = {}, ms = 8000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

interface NvdCve {
  id: string;
  vulnStatus?: string;
  published?: string;
  descriptions?: Array<{ lang: string; value: string }>;
  metrics?: Record<string, Array<{ cvssData?: { baseScore?: number; baseSeverity?: string }; baseSeverity?: string }>>;
  configurations?: Array<{ nodes?: Array<{ cpeMatch?: Array<{ criteria?: string }> }> }>;
}

export function nvdToRecord(cve: NvdCve, source: CveRecord['sources'][number]): CveRecord {
  const metric =
    cve.metrics?.cvssMetricV40?.[0] || cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
  return {
    id: cve.id,
    description: cve.descriptions?.find((d) => d.lang === 'en')?.value ?? null,
    cvssScore: metric?.cvssData?.baseScore ?? null,
    cvssSeverity: metric?.cvssData?.baseSeverity ?? metric?.baseSeverity ?? null,
    published: cve.published ?? null,
    sources: [source],
    kev: false,
    epss: null,
    epssPercentile: null,
  };
}

export async function queryNvdByCpe(cpe: string, fetchImpl: typeof fetch = fetch): Promise<CveRecord[]> {
  const url = `${NVD_API}?virtualMatchString=${encodeURIComponent(cpe)}&noRejected&resultsPerPage=500`;
  const res = await fetchWithTimeout(fetchImpl, url, { headers: nvdHeaders() }, 15000);
  if (!res.ok) throw new Error(`NVD CPE query returned ${res.status}`);
  const data = await res.json();
  return (data?.vulnerabilities || [])
    .map((v: { cve: NvdCve }) => v.cve)
    .filter((c: NvdCve) => c?.id && c.vulnStatus !== 'Rejected')
    .map((c: NvdCve) => nvdToRecord(c, 'nvd-cpe'));
}

// Keywords used to sanity-check AI-suggested CVEs against NVD's CPE data.
// Colon-anchored ':ios:' so "ios_xr_software" doesn't match classic IOS.
export const VENDOR_CPE_HINTS: Record<VendorType, string[]> = {
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
  generic: [],
};

export const VENDOR_DISPLAY_NAMES: Record<VendorType, string[]> = {
  cisco_ios: ['cisco'], cisco_nxos: ['cisco'], cisco_xr: ['cisco'], juniper: ['juniper'], arista: ['arista'],
  fortinet: ['fortinet', 'fortigate'], paloalto: ['palo alto', 'paloalto'], huawei: ['huawei'],
  aruba_hpe: ['aruba', 'hewlett packard', 'hpe'], dell_os10: ['dell'], f5_tmsh: ['f5', 'big-ip', 'bigip'],
  nokia_sros: ['nokia'], vyos: ['vyos'], extreme_exos: ['extreme'], mikrotik: ['mikrotik'], generic: [],
};

// Same OS, different hardware line: NVD's CPE data often can't tell these
// apart (an ASR-only IOS XE CVE still matches "ios_xe"), but the description
// usually names the hardware. Only added where a real mismatch was observed.
const VENDOR_HARDWARE_FAMILIES: Partial<Record<VendorType, string[][]>> = {
  cisco_ios: [
    ['catalyst'],
    ['asr'],
    ['isr', 'integrated services router'],
    ['small business', 'sf200', 'sg200', 'sf300', 'sg300', 'sf500', 'sg500', 'rv1', 'rv2', 'rv3'],
    ['nexus'],
  ],
};

function hardwareFamily(text: string, families: string[][]): number {
  const lower = (text || '').toLowerCase();
  return families.findIndex((fam) => fam.some((kw) => lower.includes(kw)));
}

/** True if the CVE description names a different hardware line than the device. */
export function isHardwareMismatch(vendor: VendorType, deviceVersionText: string, description: string | null): boolean {
  const families = VENDOR_HARDWARE_FAMILIES[vendor];
  if (!families || !description) return false;
  const own = hardwareFamily(deviceVersionText, families);
  if (own === -1) return false;
  const desc = description.toLowerCase();
  const namesOwn = families[own].some((kw) => desc.includes(kw));
  const namesOther = families.some((fam, idx) => idx !== own && fam.some((kw) => desc.includes(kw)));
  return namesOther && !namesOwn;
}

/**
 * Verifies AI-suggested CVE ids. Drops ids NVD doesn't know, ids whose CPE
 * data names a different product, and ids whose description names a
 * different hardware family. Keeps (unconfirmed) when NVD is unreachable.
 */
export async function verifyAiCandidates(
  candidates: string[],
  vendor: VendorType,
  deviceVersionText: string,
  fetchImpl: typeof fetch = fetch
): Promise<CveRecord[]> {
  const ids = Array.from(new Set(candidates.map((c) => String(c || '').trim().toUpperCase()).filter((c) => /^CVE-\d{4}-\d{4,7}$/.test(c)))).slice(0, 8);
  const hints = VENDOR_CPE_HINTS[vendor] || [];
  const names = VENDOR_DISPLAY_NAMES[vendor] || [];
  const out: CveRecord[] = [];

  for (const id of ids) {
    try {
      const res = await fetchWithTimeout(fetchImpl, `${NVD_API}?cveId=${encodeURIComponent(id)}`, { headers: nvdHeaders() }, 5000);
      if (res.status === 404) continue;
      if (!res.ok) {
        out.push({ id, description: null, cvssScore: null, cvssSeverity: null, published: null, sources: ['ai-verified'], kev: false, epss: null, epssPercentile: null });
        continue;
      }
      const cve: NvdCve | undefined = (await res.json())?.vulnerabilities?.[0]?.cve;
      if (!cve) continue;
      const record = nvdToRecord(cve, 'ai-verified');

      if (hints.length > 0) {
        const cpes = (cve.configurations || []).flatMap((c) => (c.nodes || []).flatMap((n) => (n.cpeMatch || []).map((m) => (m.criteria || '').toLowerCase())));
        if (cpes.length > 0) {
          if (!cpes.some((cpe) => hints.some((h) => cpe.includes(h)))) continue;
        } else if (record.description) {
          const desc = record.description.toLowerCase();
          if (![...hints, ...names].some((kw) => desc.includes(kw))) continue;
        }
      }
      if (isHardwareMismatch(vendor, deviceVersionText, record.description)) continue;
      out.push(record);
    } catch (err) {
      console.warn(`[!] NVD verification unreachable for ${id}; keeping it as unconfirmed:`, err);
      out.push({ id, description: null, cvssScore: null, cvssSeverity: null, published: null, sources: ['ai-verified'], kev: false, epss: null, epssPercentile: null });
    }
  }
  return out;
}

// ─── CISA KEV ───────────────────────────────────────────────────────────────

interface KevEntry {
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
}

let kevCache: { at: number; entries: Map<string, KevEntry> } | null = null;
const KEV_TTL_MS = 12 * 60 * 60 * 1000;

export async function loadKev(fetchImpl: typeof fetch = fetch, now = Date.now()): Promise<Map<string, KevEntry>> {
  if (kevCache && now - kevCache.at < KEV_TTL_MS) return kevCache.entries;
  const res = await fetchWithTimeout(fetchImpl, KEV_FEED, {}, 15000);
  if (!res.ok) throw new Error(`CISA KEV feed returned ${res.status}`);
  const data = await res.json();
  const entries = new Map<string, KevEntry>();
  for (const v of data?.vulnerabilities || []) {
    entries.set(String(v.cveID).toUpperCase(), {
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      ransomware: String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known',
    });
  }
  kevCache = { at: now, entries };
  return entries;
}

export function resetKevCache(): void {
  kevCache = null;
}

// ─── FIRST EPSS ─────────────────────────────────────────────────────────────

export async function loadEpss(ids: string[], fetchImpl: typeof fetch = fetch): Promise<Map<string, { epss: number; percentile: number }>> {
  const out = new Map<string, { epss: number; percentile: number }>();
  for (let i = 0; i < ids.length; i += 50) {
    const batch = ids.slice(i, i + 50);
    const res = await fetchWithTimeout(fetchImpl, `${EPSS_API}?cve=${batch.join(',')}`, {}, 10000);
    if (!res.ok) throw new Error(`EPSS API returned ${res.status}`);
    const data = await res.json();
    for (const row of data?.data || []) {
      out.set(String(row.cve).toUpperCase(), { epss: Number(row.epss), percentile: Number(row.percentile) });
    }
  }
  return out;
}

// ─── Cisco PSIRT openVuln (optional) ────────────────────────────────────────

const OPENVULN_OS: Record<string, string> = { ios_xe: 'iosxe', ios: 'ios' };

export async function queryCiscoOpenVuln(platform: ParsedPlatform, fetchImpl: typeof fetch = fetch): Promise<CveRecord[]> {
  const clientId = process.env.CISCO_OPENVULN_CLIENT_ID;
  const clientSecret = process.env.CISCO_OPENVULN_CLIENT_SECRET;
  const osType = OPENVULN_OS[platform.cpeProduct];
  if (!clientId || !clientSecret || platform.cpeVendor !== 'cisco' || !osType) return [];

  const tokenRes = await fetchWithTimeout(fetchImpl, 'https://id.cisco.com/oauth2/default/v1/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret }).toString(),
  });
  if (!tokenRes.ok) throw new Error(`Cisco openVuln token request returned ${tokenRes.status}`);
  const { access_token: token } = await tokenRes.json();

  const res = await fetchWithTimeout(
    fetchImpl,
    `https://apix.cisco.com/security/advisories/v2/OSType/${osType}?version=${encodeURIComponent(platform.version)}`,
    { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } },
    15000
  );
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`Cisco openVuln returned ${res.status}`);
  const data = await res.json();
  const out: CveRecord[] = [];
  for (const adv of data?.advisories || []) {
    for (const id of adv.cves || []) {
      if (!/^CVE-/i.test(id)) continue;
      out.push({
        id: String(id).toUpperCase(),
        description: adv.advisoryTitle || adv.summary || null,
        cvssScore: adv.cvssBaseScore ? Number(adv.cvssBaseScore) : null,
        cvssSeverity: adv.sir || null,
        published: adv.firstPublished || null,
        sources: ['cisco-psirt'],
        advisoryUrl: adv.publicationUrl || null,
        kev: false,
        epss: null,
        epssPercentile: null,
      });
    }
  }
  return out;
}

// ─── Orchestration ──────────────────────────────────────────────────────────

export function mergeCves(...lists: CveRecord[][]): CveRecord[] {
  const byId = new Map<string, CveRecord>();
  for (const list of lists) {
    for (const cve of list) {
      const existing = byId.get(cve.id);
      if (!existing) {
        byId.set(cve.id, { ...cve, sources: [...cve.sources] });
        continue;
      }
      existing.sources = Array.from(new Set([...existing.sources, ...cve.sources]));
      existing.description = existing.description || cve.description;
      existing.cvssScore = existing.cvssScore ?? cve.cvssScore;
      existing.cvssSeverity = existing.cvssSeverity || cve.cvssSeverity;
      existing.advisoryUrl = existing.advisoryUrl || cve.advisoryUrl;
    }
  }
  return Array.from(byId.values());
}

export function rankCves(cves: CveRecord[]): CveRecord[] {
  return [...cves].sort(
    (a, b) =>
      Number(b.kev) - Number(a.kev) ||
      (b.epss ?? -1) - (a.epss ?? -1) ||
      (b.cvssScore ?? -1) - (a.cvssScore ?? -1) ||
      a.id.localeCompare(b.id)
  );
}

export async function enrichCves(cves: CveRecord[], fetchImpl: typeof fetch = fetch, errors: string[] = []): Promise<CveRecord[]> {
  if (cves.length === 0) return cves;
  try {
    const kev = await loadKev(fetchImpl);
    for (const cve of cves) {
      const hit = kev.get(cve.id);
      if (hit) Object.assign(cve, { kev: true, kevDateAdded: hit.dateAdded, kevDueDate: hit.dueDate, kevRansomware: hit.ransomware });
    }
  } catch (err) {
    errors.push(`CISA KEV unavailable: ${err instanceof Error ? err.message : err}`);
  }
  try {
    const epss = await loadEpss(cves.map((c) => c.id), fetchImpl);
    for (const cve of cves) {
      const hit = epss.get(cve.id);
      if (hit) Object.assign(cve, { epss: hit.epss, epssPercentile: hit.percentile });
    }
  } catch (err) {
    errors.push(`EPSS unavailable: ${err instanceof Error ? err.message : err}`);
  }
  return cves;
}

export async function lookupVulnerabilities(
  vendor: VendorType,
  rawVersion: string,
  aiCandidates: string[] = [],
  fetchImpl: typeof fetch = fetch
): Promise<VulnLookupResult> {
  const errors: string[] = [];
  const sourcesQueried: string[] = [];
  const platform = parsePlatformVersion(vendor, rawVersion);
  const cpe = platform ? buildCpe(platform) : null;

  let cpeMatches: CveRecord[] = [];
  if (cpe) {
    sourcesQueried.push('NVD (CPE match)');
    try {
      cpeMatches = (await queryNvdByCpe(cpe, fetchImpl)).filter((c) => !isHardwareMismatch(vendor, rawVersion, c.description));
    } catch (err) {
      errors.push(`NVD CPE lookup failed: ${err instanceof Error ? err.message : err}`);
    }
  }

  let psirt: CveRecord[] = [];
  if (platform && process.env.CISCO_OPENVULN_CLIENT_ID) {
    sourcesQueried.push('Cisco PSIRT openVuln');
    try {
      psirt = await queryCiscoOpenVuln(platform, fetchImpl);
    } catch (err) {
      errors.push(`Cisco openVuln failed: ${err instanceof Error ? err.message : err}`);
    }
  }

  const known = new Set([...cpeMatches, ...psirt].map((c) => c.id));
  const unverified = aiCandidates.filter((id) => !known.has(String(id).toUpperCase()));
  let aiVerified: CveRecord[] = [];
  if (unverified.length) {
    sourcesQueried.push('AI suggestions (NVD-verified)');
    aiVerified = await verifyAiCandidates(unverified, vendor, rawVersion, fetchImpl);
  }

  const merged = mergeCves(cpeMatches, psirt, aiVerified);
  await enrichCves(merged, fetchImpl, errors);
  if (merged.length) sourcesQueried.push('CISA KEV', 'FIRST EPSS');

  return { platform, cpe, cves: rankCves(merged), totalMatched: merged.length, sourcesQueried, errors };
}

/**
 * Deterministic firmware risk floor.
 *   KEV-listed with CVSS >= 9, or any ransomware-linked KEV -> CRITICAL
 *   any KEV, any CVSS >= 9, 3+ CVEs, or EOL text           -> HIGH
 *   any CVE                                                -> MEDIUM
 */
export function firmwareRiskFloor(rawVersion: string, cves: CveRecord[]): RiskLevel {
  if (cves.some((c) => c.kev && ((c.cvssScore ?? 0) >= 9 || c.kevRansomware))) return 'CRITICAL';
  const eol = /end[\s-]of[\s-]life|\beol\b|obsolete|unsupported/i.test(rawVersion || '');
  if (eol || cves.some((c) => c.kev || (c.cvssScore ?? 0) >= 9) || cves.length >= 3) return 'HIGH';
  return cves.length > 0 ? 'MEDIUM' : 'LOW';
}
