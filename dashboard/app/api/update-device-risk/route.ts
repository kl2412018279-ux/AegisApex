// dashboard/app/api/update-device-risk/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';

export async function POST(req: NextRequest) {
  try {
    let body: {
      deviceId?: string;
      device_id?: string;
      riskLevel?: string;
      risk_level?: string;
    } = {};

    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        { success: false, error: 'Invalid JSON payload' },
        { status: 400 }
      );
    }

    const deviceId = body.deviceId || body.device_id;
    const riskLevel = body.riskLevel || body.risk_level;

    if (!deviceId) {
      return NextResponse.json(
        { success: false, error: 'Missing required field: deviceId' },
        { status: 400 }
      );
    }

    if (!riskLevel) {
      return NextResponse.json(
        { success: false, error: 'Missing required field: riskLevel' },
        { status: 400 }
      );
    }

    // FIX: this route previously took `riskLevel` as any string, upper-cased
    // it, and wrote it straight to the DB with no allow-list check. With no
    // auth in front of this endpoint, anyone who can reach it could set
    // ANY device to any arbitrary string as its risk_level — not just an
    // unexpected value like "TOTALLY_FINE_TRUST_ME" that would then render
    // oddly in the UI, but specifically LOW/UNASSESSED on a device that was
    // actually flagged CRITICAL, silently hiding it from the risk filter
    // and fleet posture score. The schema's own CHECK constraint on
    // public.scans.risk_level would already reject an invalid value there,
    // but devices.risk_level has no such constraint, so this was the only
    // place enforcing it — and it wasn't. Validated against the same set
    // scans.risk_level's CHECK constraint uses.
    const VALID_RISK_LEVELS = ['UNASSESSED', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const normalizedRisk = riskLevel.toUpperCase();
    if (!VALID_RISK_LEVELS.includes(normalizedRisk)) {
      return NextResponse.json(
        { success: false, error: `Invalid riskLevel "${riskLevel}". Must be one of: ${VALID_RISK_LEVELS.join(', ')}` },
        { status: 400 }
      );
    }

    // FIX: deviceId was passed straight into .eq('id', deviceId) with no
    // shape check. Supabase/Postgres will just reject a non-UUID with its
    // own error today, so this isn't a bypass — but a quick check here
    // gives a clear 400 instead of surfacing a raw Postgres error message
    // to the caller, and cheaply rules out obviously malformed input
    // before hitting the database at all.
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(deviceId)) {
      return NextResponse.json(
        { success: false, error: 'Invalid deviceId: expected a UUID.' },
        { status: 400 }
      );
    }

    const supabase = getSupabaseAdmin();
    if (!supabase) {
      return NextResponse.json(
        { success: false, error: 'Failed to initialize Supabase client' },
        { status: 500 }
      );
    }

    const nowIso = new Date().toISOString();

    // Update risk level on the devices table
    const { data: updatedDevice, error: updateErr } = await supabase
      .from('devices')
      .update({
        risk_level: normalizedRisk,
        updated_at: nowIso,
      })
      .eq('id', deviceId)
      .select('*')
      .single();

    if (updateErr) {
      console.error('[-] Error updating device risk in Supabase:', updateErr.message);
      return NextResponse.json(
        { success: false, error: updateErr.message },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      message: `Risk level updated to ${normalizedRisk} for device ${deviceId}`,
      deviceId,
      riskLevel: normalizedRisk,
      device: updatedDevice,
    });
  } catch (err: any) {
    console.error('[-] Error in /api/update-device-risk handler:', err);
    return NextResponse.json(
      { success: false, error: err?.message || 'Internal Server Error' },
      { status: 500 }
    );
  }
}
