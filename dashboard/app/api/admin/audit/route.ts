// dashboard/app/api/admin/audit/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireUser } from '@/lib/auth';
import { routeError } from '@/lib/http';
import { requireOrgAdmin } from '@/lib/adminScope';

export const dynamic = 'force-dynamic';

const Query = z.object({ orgId: z.string().uuid(), limit: z.coerce.number().int().min(1).max(500).default(100), action: z.string().max(60).optional() });

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'admin');
    const q = Query.parse(Object.fromEntries(req.nextUrl.searchParams));
    requireOrgAdmin(ctx, q.orgId);
    let query = ctx.admin.from('audit_log').select('*').eq('org_id', q.orgId).order('created_at', { ascending: false }).limit(q.limit);
    if (q.action) query = query.ilike('action', `${q.action.replace(/[%_]/g, '')}%`);
    const { data, error } = await query;
    if (error) throw error;
    return NextResponse.json({ success: true, entries: data || [] });
  } catch (err) {
    return routeError(err, 'GET /api/admin/audit');
  }
}
