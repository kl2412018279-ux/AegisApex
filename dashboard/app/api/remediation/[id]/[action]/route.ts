// dashboard/app/api/remediation/[id]/[action]/route.ts
//   approve  — admin, not the requester; queues the change for the agent
//   reject   — admin
//   rollback — admin; queues the stored rollback commands
//   cancel   — the requester (or an admin) while still pending approval
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireUser, requireDevice, roleAtLeast, roleInOrg } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { RemediationDecisionBody } from '@/lib/validation';
import { routeError, HttpError } from '@/lib/http';
import { enqueueJob } from '@/lib/collection';

const Params = z.object({ id: z.string().uuid(), action: z.enum(['approve', 'reject', 'rollback', 'cancel']) });

const ROLLBACK_FROM = ['applied', 'verified', 'verification_failed', 'failed'];

export async function POST(req: NextRequest, { params }: { params: { id: string; action: string } }) {
  try {
    const ctx = await requireUser(req, 'operator');
    const { id, action } = Params.parse(params);
    const body = RemediationDecisionBody.parse(await req.json().catch(() => ({})));

    const { data: request, error } = await ctx.admin.from('remediation_requests').select('*').eq('id', id).maybeSingle();
    if (error) throw error;
    if (!request) throw new HttpError(404, 'Change request not found');
    const device = await requireDevice(ctx, request.device_id, 'operator');
    const isAdmin = roleAtLeast(roleInOrg(ctx, device.org_id), 'admin');
    const now = new Date().toISOString();
    let update: Record<string, unknown>;

    if (action === 'cancel') {
      if (request.requested_by !== ctx.userId && !isAdmin) throw new HttpError(403, 'Only the requester or an admin can cancel this request.');
      if (request.status !== 'pending_approval') throw new HttpError(409, `Cannot cancel a request that is ${request.status}.`);
      update = { status: 'rejected', decision_note: body.note || 'Cancelled', decided_at: now };
    } else {
      if (!isAdmin) throw new HttpError(403, `Only an admin can ${action} a change.`);
      if (action === 'approve') {
        if (request.status !== 'pending_approval') throw new HttpError(409, `Cannot approve a request that is ${request.status}.`);
        if (request.requested_by === ctx.userId) throw new HttpError(403, 'Two-person rule: you cannot approve your own change request.');
        const job = await enqueueJob(ctx.admin, device.id, 'remediate', ctx.userId, { remediation_id: id });
        update = { status: 'approved', approved_by: ctx.userId, approved_by_email: ctx.email, decided_at: now, decision_note: body.note ?? null, job_id: job.id };
      } else if (action === 'reject') {
        if (request.status !== 'pending_approval') throw new HttpError(409, `Cannot reject a request that is ${request.status}.`);
        update = { status: 'rejected', approved_by: ctx.userId, approved_by_email: ctx.email, decided_at: now, decision_note: body.note ?? null };
      } else {
        if (!ROLLBACK_FROM.includes(request.status)) throw new HttpError(409, `Cannot roll back a request that is ${request.status}.`);
        if (!request.rollback_commands?.trim()) throw new HttpError(422, 'This request has no rollback commands.');
        const job = await enqueueJob(ctx.admin, device.id, 'rollback', ctx.userId, { remediation_id: id });
        update = { status: 'rolling_back', job_id: job.id, decision_note: body.note ?? request.decision_note };
      }
    }

    const { data: saved, error: saveErr } = await ctx.admin
      .from('remediation_requests')
      .update({ ...update, updated_at: now })
      .eq('id', id)
      .eq('status', request.status) // optimistic lock: fail if someone else acted first
      .select('*')
      .maybeSingle();
    if (saveErr) throw saveErr;
    if (!saved) throw new HttpError(409, 'This request was changed by someone else. Refresh and try again.');

    await audit(ctx, { action: `remediation.${action}`, orgId: device.org_id, targetType: 'remediation', targetId: id, details: { deviceId: device.id, note: body.note } });
    return NextResponse.json({ success: true, request: saved });
  } catch (err) {
    return routeError(err, 'POST /api/remediation/[id]/[action]');
  }
}
