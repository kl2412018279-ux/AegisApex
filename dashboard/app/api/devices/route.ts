// dashboard/app/api/devices/route.ts
// Inventory for the signed-in user's organizations. Read on the server so
// the browser never depends on a fixed column list (credential columns are
// hidden from browser roles, which makes select('*') fail there).
import { NextRequest, NextResponse } from 'next/server';
import { requireUser } from '@/lib/auth';
import { routeError } from '@/lib/http';
import { publicDevice } from '@/lib/deviceView';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'viewer');
    const orgIds = ctx.memberships.map((m) => m.orgId);

    let { data, error } = await ctx.admin.from('devices').select('*, suppliers(name)').in('org_id', orgIds);
    if (error) ({ data, error } = await ctx.admin.from('devices').select('*').in('org_id', orgIds));
    if (error) throw error;

    const devices = (data || [])
      .map((d) => publicDevice(d as Record<string, unknown>))
      .sort((a, b) => String(a.hostname ?? '').localeCompare(String(b.hostname ?? '')));
    return NextResponse.json({ success: true, devices });
  } catch (err) {
    return routeError(err, 'GET /api/devices');
  }
}
