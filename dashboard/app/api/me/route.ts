// dashboard/app/api/me/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { requireUser } from '@/lib/auth';
import { routeError } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'viewer');
    const { data: orgs } = await ctx.admin.from('organizations').select('id, name').in('id', ctx.memberships.map((m) => m.orgId));
    return NextResponse.json({
      success: true,
      userId: ctx.userId,
      email: ctx.email,
      memberships: ctx.memberships.map((m) => ({ ...m, orgName: orgs?.find((o) => o.id === m.orgId)?.name ?? 'Organization' })),
    });
  } catch (err) {
    return routeError(err, 'GET /api/me');
  }
}
