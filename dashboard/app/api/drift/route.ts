// dashboard/app/api/drift/route.ts
// Configuration change tracking for one device: snapshot list, the diff
// between two snapshots (default: the two most recent), and change history.
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireUser, requireDevice } from '@/lib/auth';
import { routeError, HttpError } from '@/lib/http';
import { computeDrift, withContext } from '@/lib/configDiff';

export const dynamic = 'force-dynamic';

const Query = z.object({ deviceId: z.string().uuid(), from: z.string().uuid().optional(), to: z.string().uuid().optional() });

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'viewer');
    const q = Query.parse(Object.fromEntries(req.nextUrl.searchParams));
    const device = await requireDevice(ctx, q.deviceId, 'viewer');

    const { data: snapshots, error } = await ctx.admin
      .from('configurations')
      .select('id, created_at, source')
      .eq('device_id', device.id)
      .order('created_at', { ascending: false })
      .limit(50);
    if (error) throw error;
    const { data: history } = await ctx.admin
      .from('config_changes')
      .select('id, from_configuration_id, to_configuration_id, added_lines, removed_lines, risky_changes, severity, created_at')
      .eq('device_id', device.id)
      .order('created_at', { ascending: false })
      .limit(25);

    const list = snapshots || [];
    const toId = q.to || list[0]?.id;
    const fromId = q.from || list.find((s) => s.id !== toId && s.source !== 'synthetic')?.id || list[1]?.id;
    if (!toId || !fromId) {
      return NextResponse.json({ success: true, snapshots: list, history: history || [], report: null, message: 'At least two snapshots are needed to compare.' });
    }

    const { data: pair } = await ctx.admin.from('configurations').select('id, raw_config, content, created_at').eq('device_id', device.id).in('id', [fromId, toId]);
    const from = pair?.find((p) => p.id === fromId);
    const to = pair?.find((p) => p.id === toId);
    if (!from || !to) throw new HttpError(404, 'Snapshot not found for this device');

    const report = computeDrift(from.raw_config || from.content || '', to.raw_config || to.content || '', device.netmiko_type || device.vendor || 'generic');
    return NextResponse.json({
      success: true,
      snapshots: list,
      history: history || [],
      from: { id: from.id, created_at: from.created_at },
      to: { id: to.id, created_at: to.created_at },
      report: { ...report, lines: withContext(report.lines, 3) },
    });
  } catch (err) {
    return routeError(err, 'GET /api/drift');
  }
}
