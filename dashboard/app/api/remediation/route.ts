// dashboard/app/api/remediation/route.ts
// Change requests: an operator proposes commands (usually a finding's
// remediation CLI), an admin who is NOT the requester approves, the agent
// applies them, and /api/cron/process verifies the result with the CIS rules.
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireUser, requireDevice } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { RemediationCreateBody } from '@/lib/validation';
import { readJson, routeError, HttpError } from '@/lib/http';
import { generateSmartRollback } from '@/lib/rollback';
import { queueAlert } from '@/lib/alerts';

export const dynamic = 'force-dynamic';

const ListQuery = z.object({ deviceId: z.string().uuid().optional() });

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'viewer');
    const { deviceId } = ListQuery.parse(Object.fromEntries(req.nextUrl.searchParams));
    let query = ctx.admin.from('remediation_requests').select('*, devices!inner(hostname, org_id)').order('created_at', { ascending: false }).limit(100);
    if (deviceId) {
      await requireDevice(ctx, deviceId, 'viewer');
      query = query.eq('device_id', deviceId);
    } else {
      query = query.in('devices.org_id', ctx.memberships.map((m) => m.orgId));
    }
    const { data, error } = await query;
    if (error) throw error;
    return NextResponse.json({ success: true, requests: data || [], userId: ctx.userId });
  } catch (err) {
    return routeError(err, 'GET /api/remediation');
  }
}

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'operator');
    const body = RemediationCreateBody.parse(await readJson(req));
    const device = await requireDevice(ctx, body.deviceId, 'operator');
    if (device.is_mock) throw new HttpError(422, 'Changes cannot be pushed to mock devices.');

    const rollback = body.rollbackCommands?.trim() || generateSmartRollback(body.commands, device.netmiko_type || device.vendor || 'generic').join('\n');
    const { data, error } = await ctx.admin
      .from('remediation_requests')
      .insert({
        device_id: device.id,
        rule_id: body.ruleId ?? null,
        title: body.title,
        commands: body.commands,
        rollback_commands: rollback,
        requested_by: ctx.userId,
        requested_by_email: ctx.email,
      })
      .select('*')
      .single();
    if (error) throw error;

    await queueAlert(ctx.admin, {
      orgId: device.org_id,
      deviceId: device.id,
      kind: 'remediation_pending',
      severity: 'MEDIUM',
      title: `Change awaiting approval on ${device.hostname}: ${body.title}`,
      body: `Requested by ${ctx.email ?? ctx.userId}. An admin other than the requester must approve it.`,
    });
    await audit(ctx, { action: 'remediation.request', orgId: device.org_id, targetType: 'remediation', targetId: data.id, details: { deviceId: device.id, ruleId: body.ruleId } });
    return NextResponse.json({ success: true, request: data });
  } catch (err) {
    return routeError(err, 'POST /api/remediation');
  }
}
