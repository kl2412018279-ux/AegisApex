// dashboard/lib/rateLimit.ts
// Sliding-window rate limit for routes that spend LLM / third-party quota.
// The window lives in Postgres (check_rate_limit, see
// supabase/migrations/20261015090000_rate_limits.sql) so the
// limit holds across every server instance. If that function isn't there
// yet, it falls back to a per-instance in-memory window and says so once.
import type { SupabaseClient } from '@supabase/supabase-js';
import { HttpError } from '@/lib/http';

const windows = new Map<string, number[]>();
let warnedFallback = false;

export function checkRateLimit(key: string, limit: number, windowMs: number, now = Date.now()): { ok: boolean; retryAfterSec: number } {
  const recent = (windows.get(key) || []).filter((t) => now - t < windowMs);
  if (recent.length >= limit) {
    windows.set(key, recent);
    return { ok: false, retryAfterSec: Math.ceil((windowMs - (now - recent[0])) / 1000) };
  }
  recent.push(now);
  windows.set(key, recent);
  return { ok: true, retryAfterSec: 0 };
}

async function checkShared(admin: SupabaseClient, key: string, limit: number, windowMs: number): Promise<{ ok: boolean; retryAfterSec: number } | null> {
  const { data, error } = await admin.rpc('check_rate_limit', { p_key: key, p_limit: limit, p_window_seconds: Math.ceil(windowMs / 1000) });
  if (error || !Array.isArray(data) || !data[0]) {
    if (!warnedFallback) {
      warnedFallback = true;
      console.warn('[!] check_rate_limit unavailable; using per-instance rate limits. Apply the 20261015090000 migration.', error?.message);
    }
    return null;
  }
  return { ok: !!data[0].allowed, retryAfterSec: Number(data[0].retry_after) || 0 };
}

export async function enforceRateLimit(admin: SupabaseClient, userId: string, bucket: string, limit: number, windowMs = 60_000): Promise<void> {
  const key = `${bucket}:${userId}`;
  const result = (await checkShared(admin, key, limit, windowMs)) ?? checkRateLimit(key, limit, windowMs);
  if (!result.ok) {
    throw new HttpError(429, `Rate limit exceeded for ${bucket}. Try again in ${result.retryAfterSec}s.`, {
      'Retry-After': String(result.retryAfterSec),
    });
  }
}

export function resetRateLimits(): void {
  windows.clear();
  warnedFallback = false;
}
