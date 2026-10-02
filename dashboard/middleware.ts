// dashboard/middleware.ts
//
// NEW FILE — this is the piece that was missing. Next.js only executes
// middleware from a file named exactly `middleware.ts` (or `.js`) at the
// project root (next to package.json, or in src/ if you use a src
// directory), exporting a `middleware` function and a `config.matcher`.
// You had dashboard/lib/supabase/middleware.ts with an `updateSession()`
// function, but nothing ever imported and ran it as actual Next.js
// middleware — it was dead code. Every page and every /api/* route was
// reachable with no auth check at all, regardless of the login page,
// the callback route, or updateSession()'s own logic, because none of it
// was ever being invoked on a real request.
//
// If your project uses a src/ layout, move this file to src/middleware.ts
// instead of dashboard/middleware.ts.
import { type NextRequest } from 'next/server'
import { updateSession } from '@/lib/supabase/middleware'

export async function middleware(request: NextRequest) {
  return await updateSession(request)
}

export const config = {
  matcher: [
    /*
     * Run on every request EXCEPT:
     * - _next/static, _next/image (Next.js internals)
     * - favicon.ico and common static asset extensions
     * This intentionally DOES include /api/* routes — that's what closes
     * the "no auth in front of the API" gap flagged repeatedly in earlier
     * review rounds. It also includes every page route, including /login,
     * /auth/callback, /forgot-password, /reset-password — those are
     * explicitly allow-listed inside updateSession() itself, not by
     * excluding them here, so the same file is the single source of truth
     * for which routes are public.
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
