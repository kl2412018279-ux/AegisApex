// dashboard/app/api/admin/alert-channels/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireUser } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { AlertChannelBody } from '@/lib/validation';
import { readJson, routeError, HttpError } from '@/lib/http';
import { requireOrgAdmin, maskTarget } from '@/lib/adminScope';
import { sendToChannel, type AlertChannel } from '@/lib/alerts';
import { enforceRateLimit } from '@/lib/rateLimit';

export const dynamic = 'force-dynamic';

const OrgQuery = z.object({ orgId: z.string().uuid() });
const IdQuery = z.object({ id: z.string().uuid() });

async function loadOwned(ctx: Awaited<ReturnType<typeof requireUser>>, id: string): Promise<AlertChannel> {
  const { data } = await ctx.admin.from('alert_channels').select('*').eq('id', id).maybeSingle();
  if (!data) throw new HttpError(404, 'Channel not found');
  requireOrgAdmin(ctx, data.org_id);
  return data as AlertChannel;
}

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'admin');
    const orgId = requireOrgAdmin(ctx, OrgQuery.parse(Object.fromEntries(req.nextUrl.searchParams)).orgId);
    const { data, error } = await ctx.admin.from('alert_channels').select('*').eq('org_id', orgId).order('created_at');
    if (error) throw error;
    const { data: recent } = await ctx.admin.from('alert_events').select('id, kind, severity, title, status, delivered, created_at').eq('org_id', orgId).order('created_at', { ascending: false }).limit(25);
    return NextResponse.json({
      success: true,
      channels: (data || []).map((c) => ({ ...c, target: maskTarget(c.kind, c.target) })),
      recentAlerts: recent || [],
      envChannelsConfigured: ['ALERT_SLACK_WEBHOOK_URL', 'ALERT_TEAMS_WEBHOOK_URL', 'ALERT_WEBHOOK_URL', 'ALERT_EMAIL_TO'].filter((k) => !!process.env[k]),
    });
  } catch (err) {
    return routeError(err, 'GET /api/admin/alert-channels');
  }
}

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'admin');
    const testId = req.nextUrl.searchParams.get('test');
    if (testId) {
      await enforceRateLimit(ctx.admin, ctx.userId, 'alert-test', 5);
      const channel = await loadOwned(ctx, IdQuery.parse({ id: testId }).id);
      await sendToChannel(channel, { kind: 'test', severity: 'LOW', title: 'AegisApex test alert', body: `Sent by ${ctx.email ?? ctx.userId}. If you can read this, the channel works.`, device_id: null, created_at: new Date().toISOString() });
      return NextResponse.json({ success: true });
    }

    const body = AlertChannelBody.parse(await readJson(req));
    requireOrgAdmin(ctx, body.orgId);
    const { data, error } = await ctx.admin
      .from('alert_channels')
      .insert({ org_id: body.orgId, name: body.name, kind: body.kind, target: body.target, min_severity: body.minSeverity, ...(body.events ? { events: body.events } : {}) })
      .select('*')
      .single();
    if (error) throw error;
    await audit(ctx, { action: 'alert_channel.create', orgId: body.orgId, targetType: 'alert_channel', targetId: data.id, details: { name: body.name, kind: body.kind } });
    return NextResponse.json({ success: true, channel: { ...data, target: maskTarget(data.kind, data.target) } });
  } catch (err) {
    return routeError(err, 'POST /api/admin/alert-channels');
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'admin');
    const channel = await loadOwned(ctx, IdQuery.parse(Object.fromEntries(req.nextUrl.searchParams)).id);
    await ctx.admin.from('alert_channels').delete().eq('id', channel.id);
    await audit(ctx, { action: 'alert_channel.delete', orgId: channel.org_id, targetType: 'alert_channel', targetId: channel.id, details: { name: channel.name } });
    return NextResponse.json({ success: true });
  } catch (err) {
    return routeError(err, 'DELETE /api/admin/alert-channels');
  }
}
