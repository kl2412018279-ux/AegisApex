// C:\Users\hp\aiops-securewatch\dashboard\app\api\trigger-collection\route.ts
// C:\Users\hp\aiops-securewatch\dashboard\app\api\trigger-collection\route.ts
// dashboard/app/api/trigger-collection/route.ts
import { NextRequest, NextResponse } from 'next/server';
// FIX: exec() ran `python -m agent.collector --device-id ${deviceId}` through
// a shell, so any deviceId containing shell metacharacters (`;`, `&&`, `$(...)`,
// backticks) would execute as a second command. deviceId is looked up in the
// DB first so a random string 404s before reaching exec() today, but that's
// incidental protection, not a guarantee (e.g. a future caller that skips the
// lookup, or a device.id that isn't actually DB-generated). execFile with an
// argument array never invokes a shell, so this class of bug is closed
// regardless of what deviceId contains.
import { execFile } from 'child_process';
import path from 'path';
import { getSupabaseAdmin } from '@/lib/supabase';
import { generateVendorConfig, generateVendorVersion } from '@/lib/vendor-telemetry';
import { evaluateConfigDeterministically, detectVendor } from '@/lib/cisBenchmarks';

export async function POST(req: NextRequest) {
  try {
    let body: { deviceId?: string; device_id?: string } = {};
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ success: false, error: 'Invalid JSON body' }, { status: 400 });
    }

    const deviceId = body.deviceId || body.device_id;
    if (!deviceId) {
      return NextResponse.json({ success: false, error: 'Missing required field: deviceId' }, { status: 400 });
    }

    const supabase = getSupabaseAdmin();
    if (!supabase) {
      return NextResponse.json({ success: false, error: 'Failed to initialize Supabase client' }, { status: 500 });
    }

    // 1. Device Lookup
    const { data: device, error: deviceErr } = await supabase
      .from('devices')
      .select('*')
      .eq('id', deviceId)
      .single();

    if (deviceErr || !device) {
      return NextResponse.json(
        { success: false, error: `Device not found: ${deviceErr?.message || 'Invalid ID'}` },
        { status: 404 }
      );
    }

    const ip = device.management_ip || device.ip_address || '';

    // FIX: this used to also treat *any device with no recorded IP* as a
    // mock target (`ip.startsWith('127.')` catches the empty string too,
    // since '' doesn't start with '127.' — but the client-side fallback in
    // useDashboard.ts used to default missing IPs to '127.0.0.1' for
    // display, and that value could round-trip back into a write). A real
    // device that's simply missing its management IP should be a config
    // error, not silent fake data. Only an explicit is_mock flag or an
    // actual loopback/hostname marker now routes to the mock path.
    const isMockDevice =
      device.is_mock === true ||
      ip === '127.0.0.1' ||
      ip === '0.0.0.0' ||
      device.hostname?.toLowerCase().includes('mock');

    // 2. MOCK ROUTE: Instant deterministic generation for demo devices
    if (isMockDevice) {
      console.log(`[*] Mock target detected (${device.hostname}). Generating instant telemetry.`);
      const result = await generateFallbackTelemetry(supabase, device, deviceId, 'mock_device');
      return NextResponse.json({
        success: true,
        message: `Mock telemetry generated for ${device.hostname}`,
        deviceId,
        ...result,
      });
    }

    // FIX: a real, non-mock device with no management IP at all used to
    // fall through to the live-SSH branch, immediately fail to connect
    // (empty host), and land in the same synthetic-fallback path — but
    // logged and returned as if collection had actually run. That's now a
    // clear 422 telling the operator to fix the device record.
    if (!ip) {
      return NextResponse.json(
        { success: false, error: `Device ${device.hostname} has no management IP configured. Set one before collecting telemetry.` },
        { status: 422 }
      );
    }

    // 3. LIVE SSH ROUTE: Executed on real devices / DevNet sandboxes
    console.log(`[*] Live target detected (${ip}). Launching SSH collector process.`);
    const projectRoot = path.resolve(process.cwd(), '..');

    // FIX: execFile + argument array, not a shell string (see import comment above)
    execFile('python', ['-m', 'agent.collector', '--device-id', deviceId], { cwd: projectRoot }, async (error, stdout, stderr) => {
      if (error) {
        console.error(`[-] SSH Collector error on ${ip}: ${error.message}`);
        console.log(`[*] Falling back to synthetic telemetry...`);
        // FIX: fallback data is now explicitly tagged as synthetic (see
        // generateFallbackTelemetry below) instead of being written to the
        // devices table as an indistinguishable "online" snapshot.
        await generateFallbackTelemetry(supabase, device, deviceId, 'ssh_failure_fallback');
      } else {
        console.log(`[+] SSH Collector finished:\n${stdout}`);
      }
    });

    return NextResponse.json({
      success: true,
      message: `Live SSH collection triggered for ${device.hostname}`,
      deviceId,
    });
  } catch (err: any) {
    console.error('[-] Error in trigger-collection handler:', err);
    return NextResponse.json(
      { success: false, error: err?.message || 'Internal Server Error' },
      { status: 500 }
    );
  }
}

// FIX: `source` added ('mock_device' for intentional demo devices vs.
// 'ssh_failure_fallback' when a REAL device just failed to respond). Both
// used to write connection_status: 'online' with a summary reading
// "Telemetry collected successfully", making a genuinely unreachable device
// indistinguishable in the UI from one that was actually audited. That
// matters most for a single-tenant deployment: this dashboard's whole job
// is to tell one owner which of their real devices are exposed, and a
// silently-faked "online, LOW risk" reading for an unreachable device is
// the one failure mode that defeats the tool's purpose.
async function generateFallbackTelemetry(
  supabase: any,
  device: any,
  deviceId: string,
  source: 'mock_device' | 'ssh_failure_fallback' = 'mock_device'
) {
  const vendorStr = device.netmiko_type || device.vendor || 'cisco_ios';
  const rawConfigContent = generateVendorConfig(device.hostname, vendorStr);
  const rawVersionContent = generateVendorVersion(device.hostname, vendorStr);
  const nowIso = new Date().toISOString();
  const isRealFailure = source === 'ssh_failure_fallback';
  const summaryText = isRealFailure
    ? `⚠️ SSH collection FAILED for this device. The data below is SYNTHETIC demo telemetry, not a real snapshot — verify SSH reachability and credentials, then re-run collection.`
    : `Telemetry collected successfully. Detected risk: `; // risk level appended below, same as original

  const { data: insertedConfig } = await supabase
    .from('configurations')
    .insert({
      device_id: deviceId,
      raw_config: rawConfigContent,
      content: rawConfigContent,
      created_at: nowIso,
      updated_at: nowIso,
    })
    .select('id')
    .single();

  if (insertedConfig) {
    const vendorType = detectVendor(vendorStr);
    const cisResult = evaluateConfigDeterministically(rawConfigContent, vendorType);
    const calculatedRisk = cisResult.riskLevel.toUpperCase();

    // FIX (schema-confirmed bug): public.scans has no `findings` column —
    // this insert's `findings: cisResult.findings` key was silently dropped
    // or the whole insert rejected depending on your PostgREST config, so
    // findings generated for fallback/mock telemetry were never queryable
    // later. Findings now go into `vulnerabilities` (scan_id FK), which is
    // what useDashboard.ts's read path already expects.
    const { data: scanRecord } = await supabase
      .from('scans')
      .insert({
        device_id: deviceId,
        configuration_id: insertedConfig.id,
        raw_version: rawVersionContent,
        status: 'pending_ai',
        risk_level: calculatedRisk,
        summary: isRealFailure ? `${summaryText} (Detected risk on synthetic data: ${calculatedRisk}.)` : `${summaryText}${calculatedRisk}.`,
        os_summary: isRealFailure ? `${summaryText} (Detected risk on synthetic data: ${calculatedRisk}.)` : `${summaryText}${calculatedRisk}.`,
        model_used: isRealFailure ? 'cis-rules-engine-synthetic-fallback' : 'cis-rules-engine',
        created_at: nowIso,
        updated_at: nowIso,
      })
      .select('id')
      .single();

    if (scanRecord?.id && cisResult.findings?.length > 0) {
      const severityTitleCase = (level: string): string => {
        const map: Record<string, string> = {
          CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low',
          INFORMATIONAL: 'Informational', SAFE: 'Safe',
        };
        return map[(level || '').toUpperCase()] || 'Informational';
      };
      const vulnRows = cisResult.findings.map((f: any) => ({
        scan_id: scanRecord.id,
        title: f.title || f.ruleId || 'Untitled finding',
        severity: severityTitleCase(f.severity),
        description: f.description || null,
        remediation_cli: f.remediationCli || null,
      }));
      const { error: vulnErr } = await supabase.from('vulnerabilities').insert(vulnRows);
      if (vulnErr) {
        console.warn('[!] Non-fatal error writing fallback-telemetry vulnerabilities:', vulnErr);
      }
    }

    await supabase
      .from('devices')
      .update({
        // FIX: a device that just failed live SSH collection is no longer
        // marked 'online'. 'mock_device' targets (intentional demo data)
        // keep the original 'online' behavior since that's expected there.
        connection_status: isRealFailure ? 'unreachable' : 'online',
        raw_version: rawVersionContent,
        last_config: rawConfigContent,
        last_seen: nowIso,
        last_seen_at: nowIso,
        risk_level: calculatedRisk,
      })
      .eq('id', deviceId);

    return {
      scanId: scanRecord?.id || null,
      configurationId: insertedConfig.id,
      riskLevel: calculatedRisk,
      source,
    };
  }
  return {};
}
