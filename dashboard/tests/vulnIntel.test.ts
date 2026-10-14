import { describe, it, expect, beforeEach } from 'vitest';
import {
  parsePlatformVersion, buildCpe, stripZeroPadding, lookupVulnerabilities, firmwareRiskFloor,
  resetKevCache, verifyAiCandidates, resolvePlatformCpe, resetCpeResolutionCache, type CveRecord,
} from '@/lib/vulnIntel';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

// Shapes recorded from the real NVD 2.0, CISA KEV and FIRST EPSS APIs.
const nvdCve = (id: string, score: number, desc: string, cpe = 'cpe:2.3:o:cisco:ios_xe:17.9.5:*:*:*:*:*:*:*') => ({
  cve: {
    id, vulnStatus: 'Analyzed', published: '2023-10-16T16:15:10.023',
    descriptions: [{ lang: 'en', value: desc }],
    metrics: { cvssMetricV31: [{ cvssData: { baseScore: score, baseSeverity: score >= 9 ? 'CRITICAL' : 'HIGH' } }] },
    configurations: [{ nodes: [{ cpeMatch: [{ criteria: cpe }] }] }],
  },
});

function fakeFetch(routes: Record<string, () => Response>) {
  const calls: string[] = [];
  const impl = (async (url: string) => {
    calls.push(String(url));
    const key = Object.keys(routes).find((k) => String(url).includes(k));
    if (!key) throw new Error(`unexpected fetch ${url}`);
    return routes[key]();
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe('parsePlatformVersion', () => {
  it.each([
    ['cisco_ios', 'Cisco IOS XE Software, Version 17.09.05\nCisco IOS Software [Cupertino]', 'cpe:2.3:o:cisco:ios_xe:17.9.5:*'],
    ['cisco_ios', 'Cisco IOS Software, C2960 Software, Version 15.2(4)M7, RELEASE', 'cpe:2.3:o:cisco:ios:15.2\\(4\\)m7:*'],
    ['cisco_nxos', 'NXOS: version 9.3(8)', 'cpe:2.3:o:cisco:nx-os:9.3\\(8\\):*'],
    ['juniper', 'Junos: 21.4R3-S5.4', 'cpe:2.3:o:juniper:junos:21.4:r3-s5'],
    ['arista', 'Software image version: 4.28.3M', 'cpe:2.3:o:arista:eos:4.28.3m:*'],
    ['fortinet', 'Version: FortiGate-100F v7.2.5,build1517,230606', 'cpe:2.3:o:fortinet:fortios:7.2.5:*'],
    ['paloalto', 'sw-version: 10.2.4-h4', 'cpe:2.3:o:paloaltonetworks:pan-os:10.2.4:h4'],
    ['mikrotik', 'version: 7.11.2 (stable)', 'cpe:2.3:o:mikrotik:routeros:7.11.2:*'],
  ] as const)('%s', (vendor, text, cpe) => {
    const parsed = parsePlatformVersion(vendor, text);
    expect(parsed).not.toBeNull();
    expect(buildCpe(parsed!)).toBe(cpe);
  });

  it('returns null when the version text has no parsable version', () => {
    expect(parsePlatformVersion('huawei', 'VRP (R) software, Version 8.180')).toBeNull();
  });

  it.each([
    ['huawei', 'VRP (R) software, Version 8.180 (CE6800 V200R005C10SPC607B607)', 'huawei', 'ce6800_firmware', 'v200r005c10'],
    ['dell_os10', 'Dell EMC Networking OS10 Enterprise\nOS Version: 10.5.4.3', 'dell', 'emc_networking_os10', '10.5.4.3'],
    ['nokia_sros', 'TiMOS-C-22.10.R2 cpm/hops64 Nokia 7750 SR', 'nokia', 'sr_os', '22.10.r2'],
    ['vyos', 'Version:          VyOS 1.4.0', 'vyos', 'vyos', '1.4.0'],
    ['aruba_hpe', 'ArubaOS-CX\nVersion      : FL.10.10.1010', 'arubanetworks', 'arubaos-cx', '10.10.1010'],
    ['aruba_hpe', 'HPE Comware Platform Software\nComware Software, Version 7.1.070, Release 3208P08', 'hp', 'comware', '7.1.070'],
  ] as const)('%s with candidate names (%s)', (vendor, text, cpeVendor, cpeProduct, version) => {
    const p = parsePlatformVersion(vendor, text);
    expect(p).toMatchObject({ cpeVendor, cpeProduct, version });
    expect(p!.alternatives).toBeDefined();
  });

  it('strips zero padding', () => {
    expect(stripZeroPadding('17.09.04a')).toBe('17.9.4a');
  });
});

describe('lookupVulnerabilities', () => {
  beforeEach(() => resetKevCache());

  it('finds CVEs by CPE, enriches with KEV + EPSS and ranks exploited first', async () => {
    const { impl, calls } = fakeFetch({
      'virtualMatchString': () => json({ vulnerabilities: [
        nvdCve('CVE-2023-1111', 7.5, 'Catalyst switches running IOS XE ...'),
        nvdCve('CVE-2023-20198', 10, 'Cisco IOS XE web UI privilege escalation'),
      ] }),
      'known_exploited_vulnerabilities': () => json({ vulnerabilities: [
        { cveID: 'CVE-2023-20198', dateAdded: '2023-10-16', dueDate: '2023-10-20', knownRansomwareCampaignUse: 'Unknown' },
      ] }),
      'api.first.org': () => json({ data: [
        { cve: 'CVE-2023-20198', epss: '0.94', percentile: '0.99' },
        { cve: 'CVE-2023-1111', epss: '0.01', percentile: '0.30' },
      ] }),
    });
    const result = await lookupVulnerabilities('cisco_ios', 'Cisco IOS XE Software, Version 17.09.05', [], impl);
    expect(result.cpe).toBe('cpe:2.3:o:cisco:ios_xe:17.9.5:*');
    expect(result.cves.map((c) => c.id)).toEqual(['CVE-2023-20198', 'CVE-2023-1111']);
    expect(result.cves[0]).toMatchObject({ kev: true, epss: 0.94, cvssScore: 10 });
    expect(result.errors).toEqual([]);
    expect(calls.some((u) => u.includes('virtualMatchString=cpe%3A2.3%3Ao%3Acisco%3Aios_xe%3A17.9.5'))).toBe(true);
  });

  it('drops CPE matches whose description names a different hardware family', async () => {
    const { impl } = fakeFetch({
      'virtualMatchString': () => json({ vulnerabilities: [nvdCve('CVE-2023-20187', 8.6, 'Cisco ASR 1000 Series Aggregation Services Routers L2TP')] }),
      'known_exploited': () => json({ vulnerabilities: [] }),
      'api.first.org': () => json({ data: [] }),
    });
    const result = await lookupVulnerabilities('cisco_ios', 'Cisco IOS XE Software, Version 17.09.05\ncisco C9300-48P (catalyst)', [], impl);
    expect(result.cves).toEqual([]);
  });

  it('keeps working and reports errors when enrichment feeds are down', async () => {
    const { impl } = fakeFetch({
      'virtualMatchString': () => json({ vulnerabilities: [nvdCve('CVE-2024-1', 5, 'IOS XE issue')] }),
      'known_exploited': () => json({}, 503),
      'api.first.org': () => json({}, 503),
    });
    const result = await lookupVulnerabilities('cisco_ios', 'Cisco IOS XE Software, Version 17.09.05', [], impl);
    expect(result.cves).toHaveLength(1);
    expect(result.errors.join(' ')).toMatch(/KEV.*503/);
  });
});

describe('resolvePlatformCpe', () => {
  beforeEach(() => resetCpeResolutionCache());

  it('uses the first candidate the NVD CPE dictionary knows, and caches it', async () => {
    const p = parsePlatformVersion('dell_os10', 'OS Version: 10.5.4.3')!;
    const { impl, calls } = fakeFetch({
      'emc_networking_os10': () => json({ totalResults: 0, products: [] }),
      'networking_os10': () => json({ totalResults: 3, products: [{}] }),
    });
    expect(await resolvePlatformCpe(p, impl)).toBe('cpe:2.3:o:dell:networking_os10:10.5.4.3:*');
    expect(await resolvePlatformCpe(p, impl)).toBe('cpe:2.3:o:dell:networking_os10:10.5.4.3:*');
    expect(calls).toHaveLength(2);
  });

  it('returns null when no candidate exists, and lookup says why', async () => {
    const { impl } = fakeFetch({ 'cpes/2.0': () => json({ totalResults: 0 }) });
    const result = await lookupVulnerabilities('vyos', 'Version: VyOS 1.4.0', [], impl);
    expect(result.cpe).toBeNull();
    expect(result.errors.join(' ')).toMatch(/no entry for VyOS 1\.4\.0/);
  });

  it('makes no dictionary request for platforms with one well-known name', async () => {
    const { impl, calls } = fakeFetch({});
    expect(await resolvePlatformCpe(parsePlatformVersion('juniper', 'Junos: 21.4R3-S5')!, impl)).toBe('cpe:2.3:o:juniper:junos:21.4:r3-s5');
    expect(calls).toHaveLength(0);
  });
});

describe('verifyAiCandidates', () => {
  it('drops ids NVD does not know and ids for other products', async () => {
    const { impl } = fakeFetch({
      'CVE-2099-0001': () => json({}, 404),
      'CVE-2024-37064': () => json({ vulnerabilities: [{ cve: { id: 'CVE-2024-37064', descriptions: [{ lang: 'en', value: 'ydata-profiling deserialization' }] } }] }),
      'CVE-2023-20198': () => json({ vulnerabilities: [nvdCve('CVE-2023-20198', 10, 'Cisco IOS XE web UI')] }),
    });
    const out = await verifyAiCandidates(['CVE-2099-0001', 'CVE-2024-37064', 'CVE-2023-20198', 'not-a-cve'], 'cisco_ios', 'IOS XE', impl);
    expect(out.map((c) => c.id)).toEqual(['CVE-2023-20198']);
  });
});

describe('firmwareRiskFloor', () => {
  const cve = (over: Partial<CveRecord>): CveRecord => ({ id: 'CVE-1', description: null, cvssScore: 5, cvssSeverity: null, published: null, sources: ['nvd-cpe'], kev: false, epss: null, epssPercentile: null, ...over });

  it('is CRITICAL for an exploited critical CVE', () => {
    expect(firmwareRiskFloor('', [cve({ kev: true, cvssScore: 10 })])).toBe('CRITICAL');
  });
  it('is HIGH for any exploited CVE', () => {
    expect(firmwareRiskFloor('', [cve({ kev: true, cvssScore: 6 })])).toBe('HIGH');
  });
  it('is HIGH for end-of-life software', () => {
    expect(firmwareRiskFloor('This release is End-of-Life', [])).toBe('HIGH');
  });
  it('is MEDIUM for a single ordinary CVE and LOW for none', () => {
    expect(firmwareRiskFloor('', [cve({})])).toBe('MEDIUM');
    expect(firmwareRiskFloor('', [])).toBe('LOW');
  });
});
