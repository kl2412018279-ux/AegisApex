//C:\Users\hp\aiops-securewatch\dashboard\lib\supabase.ts
import { createClient, SupabaseClient } from '@supabase/supabase-js';

let _clientInstance: SupabaseClient | null = null;
let _adminInstance: SupabaseClient | null = null;

function getEnvVars() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY;

  return { url, anonKey, serviceKey };
}

/**
 * Lazy-initialized browser-safe Supabase client. Respects RLS.
 */
export function getSupabaseClient(): SupabaseClient {
  if (!_clientInstance) {
    const { url, anonKey } = getEnvVars();
    if (!url || !anonKey) {
      throw new Error(
        'Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_ANON_KEY. ' +
          'Ensure these variables are defined in your environment.'
      );
    }
    _clientInstance = createClient(url, anonKey);
  }
  return _clientInstance;
}

/**
 * Browser-safe client export.
 * Proxied to lazy-load on access, preventing build-time static evaluation crashes.
 */
export const supabase: SupabaseClient = new Proxy({} as SupabaseClient, {
  get(_target, prop: keyof SupabaseClient) {
    const instance = getSupabaseClient();
    const value = instance[prop];
    return typeof value === 'function' ? value.bind(instance) : value;
  },
});

/**
 * Server-only, service-role client for API route handlers and server components.
 * Explicitly blocks execution within browser runtimes.
 */
export function getSupabaseAdmin(): SupabaseClient {
  if (typeof window !== 'undefined') {
    throw new Error(
      'Security Error: Attempted to call getSupabaseAdmin() in a client context. ' +
        'Service-role administrative clients must never run in the browser.'
    );
  }

  const { url, serviceKey } = getEnvVars();

  if (!url || !serviceKey) {
    throw new Error(
      'Missing SUPABASE_SERVICE_ROLE_KEY or NEXT_PUBLIC_SUPABASE_URL. ' +
        'Refusing to fall back to the anon key for administrative operations.'
    );
  }

  if (!_adminInstance) {
    _adminInstance = createClient(url, serviceKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });
  }

  return _adminInstance;
}