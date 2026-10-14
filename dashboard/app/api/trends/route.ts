// dashboard/app/api/trends/route.ts
// Fleet risk trend and compliance posture for every org the caller belongs to.
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireUser } from '@/lib/auth';
import { routeError } from '@/lib/http';
import { buildTrend, type HistoryRow } from '@/lib/trends';
import { computeCompliance, loadDeviceFindings } from '@/lib/compliance';

export const dynamic = 'force-dynamic';

const Query = z.object({ days: z.coerce.number().int().min(7).max(365).default(30) });

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'viewer');
    const { days } = Query.parse(Object.fromEntries(req.nextUrl.searchParams));
    const orgIds = ctx.memberships.map((m) => m.orgId);
    const { data: devices } = await ctx.admin.from('devices').select('id, hostname, vendor, netmiko_type').in('org_id', orgIds);
    const ids = (devices || []).map((d) => d.id);

    const since = new Date(Date.now() - days * 86_400_000);
    const seedSince = new Date(since.getTime() - 90 * 86_400_000);
    const { data: history } = ids.length
      ? await ctx.admin
          .from('risk_history')
          .select('device_id, risk_level, source, findings_count, rules_evaluated, recorded_at')
          .in('device_id', ids)
          .gte('recorded_at', seedSince.toISOString())
          .order('recorded_at', { ascending: true })
          .limit(50_000)
      : { data: [] };

    const compliance = computeCompliance(await loadDeviceFindings(ctx.admin, devices || []));
    return NextResponse.json({ success: true, days, trend: buildTrend((history || []) as HistoryRow[], since), compliance });
  } catch (err) {
    return routeError(err, 'GET /api/trends');
  }
}
