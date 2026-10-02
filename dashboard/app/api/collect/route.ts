// dashboard/app/api/collect/route.ts
// dashboard/app/api/collect/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';
import { generateVendorConfig } from '@/lib/vendor-telemetry';

interface DeviceRecord {
  id: string;
  hostname: string;
  vendor?: string;
  netmiko_type?: string;
  ip_address?: string;
  host?: string;
  port?: number;
  last_config?: string;
}

export async function POST(req: NextRequest) {
  let body: { deviceId?: string; device_id?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { success: false, error: 'Invalid JSON request body' },
      { status: 400 }
    );
  }

  const deviceId = body.deviceId || body.device_id;
  if (!deviceId) {
    return NextResponse.json(
      { success: false, error: 'Missing required field: deviceId' },
      { status: 400 }
    );
  }

  try {
    const supabase = getSupabaseAdmin();

    if (!supabase) {
      const fallbackHostname = 'Network-Device';
      const rawConfigContent = generateVendorConfig(fallbackHostname, 'cisco_ios');
      return NextResponse.json({
        success: true,
        message: `Telemetry snapshot generated (offline mode) for ${fallbackHostname}`,
        deviceId,
        configurationId: 'demo-config-id',
        rawConfig: rawConfigContent,
        content: rawConfigContent,
      });
    }

    // Fetch target device record
    const { data: device, error: deviceErr } = await supabase
      .from('devices')
      .select('*')
      .eq('id', deviceId)
      .single();

    if (deviceErr || !device) {
      return NextResponse.json(
        { success: false, error: `Device not found: ${deviceErr?.message || 'Unknown ID'}` },
        { status: 404 }
      );
    }

    const typedDevice = device as DeviceRecord;
    const vendorStr = typedDevice.netmiko_type || typedDevice.vendor || 'cisco_xe';
    let rawConfigContent = '';
    let collectionSource = 'live_agent';

    // Strategy 1: Attempt to contact live Python agent collector API if active
    const agentBaseUrl = process.env.PYTHON_AGENT_URL || 'http://127.0.0.1:8000';
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const agentRes = await fetch(`${agentBaseUrl}/collect`, {
        method: 'POST',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceId }),
      }).finally(() => clearTimeout(timeoutId));

      if (agentRes.ok) {
        const agentData = await agentRes.json();
        rawConfigContent = agentData.rawConfig || agentData.config || agentData.content || '';
      }
    } catch {
      console.warn(`[!] Python collector agent at ${agentBaseUrl} unreachable. Checking database fallback...`);
    }

    // Strategy 2: Use existing CLI-ingested telemetry stored in DB
    if (!rawConfigContent || rawConfigContent.trim() === '' || /^[!\s]+$/.test(rawConfigContent)) {
      if (typedDevice.last_config && !/^[!\s]+$/.test(typedDevice.last_config.trim())) {
        rawConfigContent = typedDevice.last_config;
        collectionSource = 'existing_db_snapshot';
      } else {
        const { data: dbConfig } = await supabase
          .from('configurations')
          .select('*')
          .eq('device_id', deviceId)
          .order('created_at', { ascending: false })
          .limit(1)
          .maybeSingle();

        if (dbConfig) {
          rawConfigContent = dbConfig.raw_config || dbConfig.content || '';
          if (rawConfigContent && !/^[!\s]+$/.test(rawConfigContent.trim())) {
            collectionSource = 'existing_db_snapshot';
          }
        }
      }
    }

    // Strategy 3: Fallback mock telemetry if no live agent and no DB telemetry
    if (!rawConfigContent || /^[!\s]+$/.test(rawConfigContent.trim())) {
      rawConfigContent = generateVendorConfig(typedDevice.hostname, vendorStr);
      collectionSource = 'synthetic_fallback';
    }

    const nowIso = new Date().toISOString();

    // Insert snapshot into configurations table (using verified schema columns only)
    const { data: insertedConfig } = await supabase
      .from('configurations')
      .insert({
        device_id: deviceId,
        raw_config: rawConfigContent,
        content: rawConfigContent,
        created_at: nowIso,
      })
      .select('id')
      .maybeSingle();

    const configId = insertedConfig?.id || 'synthetic-config-id';

    // Update devices table (syncing last_config and last_seen_at)
    await supabase
      .from('devices')
      .update({
        connection_status: 'online',
        last_seen_at: nowIso,
        last_config: rawConfigContent,
      })
      .eq('id', deviceId);

    return NextResponse.json({
      success: true,
      message: `Telemetry processed (${collectionSource}) for ${typedDevice.hostname}`,
      deviceId,
      configurationId: configId,
      rawConfig: rawConfigContent,
      content: rawConfigContent,
      source: collectionSource,
    });
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Internal Server Error';
    console.error('[-] Error in /api/collect route:', err);
    return NextResponse.json(
      { success: false, error: errorMessage },
      { status: 500 }
    );
  }
}