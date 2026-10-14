// dashboard/lib/audit.ts
import type { AuthContext } from '@/lib/auth';

export interface AuditEntry {
  action: string;
  orgId?: string | null;
  targetType?: string;
  targetId?: string | null;
  details?: Record<string, unknown>;
}

/** Records who did what. Never throws: a failed audit write is logged, not fatal. */
export async function audit(ctx: AuthContext, entry: AuditEntry): Promise<void> {
  const { error } = await ctx.admin.from('audit_log').insert({
    org_id: entry.orgId ?? ctx.memberships[0]?.orgId ?? null,
    actor_id: ctx.userId,
    actor_email: ctx.email,
    action: entry.action,
    target_type: entry.targetType ?? null,
    target_id: entry.targetId ?? null,
    details: entry.details ?? null,
    ip: ctx.ip,
  });
  if (error) console.error(`[-] audit_log write failed for ${entry.action}:`, error);
}
