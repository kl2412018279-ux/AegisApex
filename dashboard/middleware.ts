// dashboard/middleware.ts
// Runs updateSession() on every page and API request. Public routes are
// allow-listed inside updateSession() so there is one source of truth.
import { type NextRequest } from 'next/server'
import { updateSession } from '@/lib/supabase/middleware'

export async function middleware(request: NextRequest) {
  return await updateSession(request)
}

export const config = {
  matcher: [
    // Everything except Next.js internals and static assets, including /api/*.
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
