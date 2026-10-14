// dashboard/lib/supabase.ts
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { createBrowserClient } from '@supabase/ssr';

let _clientInstance: SupabaseClient | null = null;
let _adminInstance: SupabaseClient | null = null;

function publicKey(): string | undefined {
  return process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
}

/**
 * Browser client bound to the signed-in user's session cookie, so Row Level
 * Security evaluates as that user. Read-only by policy: all writes go
 * through the API routes.
 */
export function getSupabaseClient(): SupabaseClient {
  if (!_clientInstance) {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = publicKey();
    if (!url || !key) {
      throw new Error('Missing NEXT_PUBLIC_SUPABASE_URL or a public Supabase key (NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY / NEXT_PUBLIC_SUPABASE_ANON_KEY).');
    }
    _clientInstance = createBrowserClient(url, key);
  }
  return _clientInstance;
}

/** Lazily resolved so importing this module during a build doesn't need env vars. */
export const supabase: SupabaseClient = new Proxy({} as SupabaseClient, {
  get(_target, prop: keyof SupabaseClient) {
    const instance = getSupabaseClient();
    const value = instance[prop];
    return typeof value === 'function' ? value.bind(instance) : value;
  },
});

/**
 * Server-only service-role client. Bypasses RLS, so callers must authorize
 * the request themselves (see lib/auth.ts) before using it.
 */
export function getSupabaseAdmin(): SupabaseClient {
  if (typeof window !== 'undefined') {
    throw new Error('getSupabaseAdmin() must never run in the browser.');
  }
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY;
  if (!url || !serviceKey) {
    throw new Error('Missing SUPABASE_SERVICE_ROLE_KEY or NEXT_PUBLIC_SUPABASE_URL. Refusing to fall back to the anon key.');
  }
  if (!_adminInstance) {
    _adminInstance = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });
  }
  return _adminInstance;
}
