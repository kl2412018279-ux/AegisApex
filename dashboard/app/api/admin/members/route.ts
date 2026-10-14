// dashboard/app/api/admin/members/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireUser } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { MemberBody } from '@/lib/validation';
import { readJson, routeError, HttpError } from '@/lib/http';
import { requireOrgAdmin } from '@/lib/adminScope';

export const dynamic = 'force-dynamic';

const OrgQuery = z.object({ orgId: z.string().uuid() });
const DeleteQuery = z.object({ orgId: z.string().uuid(), userId: z.string().uuid() });

async function emailsById(admin: import('@supabase/supabase-js').SupabaseClient): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  for (let page = 1; page <= 20; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 1000 });
    if (error) throw error;
    for (const u of data.users) map.set(u.id, u.email ?? '');
    if (data.users.length < 1000) break;
  }
  return map;
}

async function adminCount(admin: import('@supabase/supabase-js').SupabaseClient, orgId: string): Promise<number> {
  const { count } = await admin.from('org_members').select('user_id', { count: 'exact', head: true }).eq('org_id', orgId).eq('role', 'admin');
  return count ?? 0;
}

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'admin');
    const orgId = requireOrgAdmin(ctx, OrgQuery.parse(Object.fromEntries(req.nextUrl.searchParams)).orgId);
    const { data, error } = await ctx.admin.from('org_members').select('user_id, role, created_at').eq('org_id', orgId).order('created_at');
    if (error) throw error;
    const emails = await emailsById(ctx.admin);
    return NextResponse.json({ success: true, members: (data || []).map((m) => ({ ...m, email: emails.get(m.user_id) ?? '(deleted user)' })) });
  } catch (err) {
    return routeError(err, 'GET /api/admin/members');
  }
}

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'admin');
    const body = MemberBody.parse(await readJson(req));
    const orgId = requireOrgAdmin(ctx, body.orgId);

    const emails = await emailsById(ctx.admin);
    let userId = Array.from(emails.entries()).find(([, e]) => e.toLowerCase() === body.email.toLowerCase())?.[0];
    let invited = false;
    if (!userId) {
      const { data, error } = await ctx.admin.auth.admin.inviteUserByEmail(body.email);
      if (error) throw new HttpError(400, `Could not invite ${body.email}: ${error.message}`);
      userId = data.user.id;
      invited = true;
    }

    const { data: existing } = await ctx.admin.from('org_members').select('role').eq('org_id', orgId).eq('user_id', userId).maybeSingle();
    if (existing?.role === 'admin' && body.role !== 'admin' && (await adminCount(ctx.admin, orgId)) <= 1) {
      throw new HttpError(409, 'An organization must keep at least one admin.');
    }
    const { error } = await ctx.admin.from('org_members').upsert({ org_id: orgId, user_id: userId, role: body.role }, { onConflict: 'org_id,user_id' });
    if (error) throw error;

    await audit(ctx, { action: invited ? 'member.invite' : 'member.role', orgId, targetType: 'user', targetId: userId, details: { email: body.email, role: body.role, from: existing?.role ?? null } });
    return NextResponse.json({ success: true, userId, invited });
  } catch (err) {
    return routeError(err, 'POST /api/admin/members');
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'admin');
    const { orgId: rawOrg, userId } = DeleteQuery.parse(Object.fromEntries(req.nextUrl.searchParams));
    const orgId = requireOrgAdmin(ctx, rawOrg);
    const { data: existing } = await ctx.admin.from('org_members').select('role').eq('org_id', orgId).eq('user_id', userId).maybeSingle();
    if (!existing) throw new HttpError(404, 'Member not found');
    if (existing.role === 'admin' && (await adminCount(ctx.admin, orgId)) <= 1) throw new HttpError(409, 'An organization must keep at least one admin.');
    await ctx.admin.from('org_members').delete().eq('org_id', orgId).eq('user_id', userId);
    await audit(ctx, { action: 'member.remove', orgId, targetType: 'user', targetId: userId, details: { role: existing.role } });
    return NextResponse.json({ success: true });
  } catch (err) {
    return routeError(err, 'DELETE /api/admin/members');
  }
}
