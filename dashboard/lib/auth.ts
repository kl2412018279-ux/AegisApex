// dashboard/lib/auth.ts
// Per-route authorization. Middleware already rejects requests with no
// session, but every API route also checks here so a middleware bypass
// (e.g. CVE-2025-29927) or a misconfigured matcher can't expose the API.
import type { SupabaseClient } from '@supabase/supabase-js';
import { createClient as createSessionClient } from '@/lib/supabase/server';
import { getSupabaseAdmin } from '@/lib/supabase';
import { HttpError, clientIp } from '@/lib/http';

export type Role = 'viewer' | 'operator' | 'admin';

const ROLE_RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

export interface Membership {
  orgId: string;
  role: Role;
}

export interface AuthContext {
  userId: string;
  email: string | null;
  memberships: Membership[];
  ip: string | null;
  admin: SupabaseClient;
}

export function roleAtLeast(role: Role | undefined, min: Role): boolean {
  return !!role && ROLE_RANK[role] >= ROLE_RANK[min];
}

export function roleInOrg(ctx: AuthContext, orgId: string | null | undefined): Role | undefined {
  return ctx.memberships.find((m) => m.orgId === orgId)?.role;
}

export function orgIdsWithRole(ctx: AuthContext, min: Role): string[] {
  return ctx.memberships.filter((m) => roleAtLeast(m.role, min)).map((m) => m.orgId);
}

/** Resolves the signed-in user and their org memberships, or throws 401/403. */
export async function requireUser(req: Request, min: Role = 'viewer'): Promise<AuthContext> {
  const session = await createSessionClient();
  const { data, error } = await session.auth.getUser();
  if (error || !data.user) throw new HttpError(401, 'Unauthorized');

  const admin = getSupabaseAdmin();
  const { data: rows, error: roleErr } = await admin
    .from('org_members')
    .select('org_id, role')
    .eq('user_id', data.user.id);
  if (roleErr) {
    console.error('[-] org_members lookup failed:', roleErr);
    throw new HttpError(500, 'Role lookup failed. Has supabase/migrations/20261014120000_aegisapex_upgrades.sql been applied?');
  }

  const ctx: AuthContext = {
    userId: data.user.id,
    email: data.user.email ?? null,
    memberships: (rows || []).map((r: { org_id: string; role: Role }) => ({ orgId: r.org_id, role: r.role })),
    ip: clientIp(req),
    admin,
  };

  if (!ctx.memberships.some((m) => roleAtLeast(m.role, min))) {
    throw new HttpError(403, `This action requires the ${min} role.`);
  }
  return ctx;
}

/**
 * Loads a device and checks the caller has at least `min` in its org.
 * Returns 404 (not 403) when the caller has no membership at all, so device
 * ids from other organizations can't be probed.
 */
export async function requireDevice<T = Record<string, any>>(
  ctx: AuthContext,
  deviceId: string,
  min: Role
): Promise<T & { id: string; org_id: string }> {
  const { data: device, error } = await ctx.admin.from('devices').select('*').eq('id', deviceId).maybeSingle();
  if (error) throw error;
  const role = device ? roleInOrg(ctx, device.org_id) : undefined;
  if (!device || !role) throw new HttpError(404, 'Device not found');
  if (!roleAtLeast(role, min)) throw new HttpError(403, `This action requires the ${min} role for this device's organization.`);
  return device;
}

/** Cron endpoints authenticate with CRON_SECRET (Vercel sends it as a bearer token). */
export function requireCron(req: Request): void {
  const secret = process.env.CRON_SECRET;
  if (!secret) throw new HttpError(503, 'CRON_SECRET is not configured');
  if (req.headers.get('authorization') !== `Bearer ${secret}`) throw new HttpError(401, 'Unauthorized');
}
