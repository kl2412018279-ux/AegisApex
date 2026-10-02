// dashboard/lib/supabase/server.ts
// dashboard/lib/supabase/server.ts
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

// FIX (same as lib/supabase/client.ts): fallback to NEXT_PUBLIC_SUPABASE_ANON_KEY
// so this doesn't depend on which key-naming convention your project uses.
//
// FIX: `cookies()` from `next/headers` is async as of recent Next.js
// versions — calling it without `await` (as the version you added did)
// either throws or silently gets a Promise where a cookie store was
// expected, depending on your exact Next.js version. `createClient` is
// already `async` in your auth/callback/route.ts caller (`await
// createClient()`), so awaiting here is consistent with how it's already
// being called.
export async function createClient() {
  const cookieStore = await cookies()

  const supabaseKey =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

  if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !supabaseKey) {
    throw new Error(
      'Missing NEXT_PUBLIC_SUPABASE_URL or a public Supabase key ' +
      '(NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY / NEXT_PUBLIC_SUPABASE_ANON_KEY).'
    )
  }

  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, supabaseKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll()
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) =>
            cookieStore.set(name, value, options)
          )
        } catch {
          // The `setAll` method was called from a Server Component.
          // This can be ignored if middleware is refreshing user sessions.
        }
      },
    },
  })
}
