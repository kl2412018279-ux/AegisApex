// dashboard/lib/rateLimit.ts
// Sliding-window limiter for the routes that spend LLM / third-party API
// quota. State is per server instance, so on a multi-instance deployment the
// effective limit is (limit × instances) — enough to stop a runaway loop or a
// single abusive session, which is what it's for.
import { HttpError } from '@/lib/http';

const windows = new Map<string, number[]>();

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

export function enforceRateLimit(userId: string, bucket: string, limit: number, windowMs = 60_000): void {
  const { ok, retryAfterSec } = checkRateLimit(`${bucket}:${userId}`, limit, windowMs);
  if (!ok) {
    throw new HttpError(429, `Rate limit exceeded for ${bucket}. Try again in ${retryAfterSec}s.`, {
      'Retry-After': String(retryAfterSec),
    });
  }
}

export function resetRateLimits(): void {
  windows.clear();
}
