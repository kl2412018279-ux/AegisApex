// dashboard/lib/adminScope.ts
import { roleAtLeast, roleInOrg, type AuthContext } from './auth';
import { HttpError } from './http';

export function requireOrgAdmin(ctx: AuthContext, orgId: string | null | undefined): string {
  if (!orgId || !roleAtLeast(roleInOrg(ctx, orgId), 'admin')) throw new HttpError(403, 'Admin role required for this organization.');
  return orgId;
}

/** Webhook URLs carry their own credentials: show only enough to recognise them. */
export function maskTarget(kind: string, target: string): string {
  if (kind === 'email') return target;
  try {
    const url = new URL(target);
    return `${url.protocol}//${url.host}/…${target.slice(-4)}`;
  } catch {
    return '…' + target.slice(-4);
  }
}
