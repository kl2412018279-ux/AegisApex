// C:\Users\hp\aiops-securewatch\dashboard\lib\supabase\middleware.ts
// dashboard/lib/supabase/middleware.ts
import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

export async function updateSession(request: NextRequest) {
  let supabaseResponse = NextResponse.next({
    request,
  })

  const supabaseKey =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    supabaseKey!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll()
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value))
          supabaseResponse = NextResponse.next({
            request,
          })
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          )
        },
      },
    }
  )

  // Validates user session without relying solely on unchecked local state
  const {
    data: { user },
  } = await supabase.auth.getUser()

  const { pathname } = request.nextUrl
  const isApiRoute = pathname.startsWith('/api')
  const isLoginPage = pathname.startsWith('/login')
  const isAuthCallback = pathname.startsWith('/auth')
  // FIX: forgot-password and reset-password weren't in the original
  // allow-list at all. Since this file previously had no root middleware.ts
  // actually wiring it up (see dashboard/middleware.ts, added in this
  // delivery), that gap was invisible until now — with the matcher active,
  // an unauthenticated visitor to /forgot-password would have been
  // redirected straight to /login, making "Forgot password?" a dead link.
  const isPublicAuthPage =
    isLoginPage || isAuthCallback || pathname.startsWith('/forgot-password') || pathname.startsWith('/reset-password')

  // Unauthenticated request to anything else
  if (!user && !isPublicAuthPage) {
    // FIX: API routes now get a 401 JSON body instead of a 307 redirect to
    // /login. A redirect response to a `fetch()` call either gets silently
    // followed (returning the login PAGE's HTML where the caller expected
    // JSON, which then fails to parse as JSON and shows a confusing error)
    // or, depending on fetch mode, gets reported as an opaque failure.
    // Every /api/* route this project has (scan, trigger-collection,
    // analyze-impact, analyze-firmware, update-device-risk) previously had
    // no auth check in front of it at all — this is what actually closes
    // that gap, but only once dashboard/middleware.ts's matcher includes
    // /api paths (it does, see that file).
    if (isApiRoute) {
      return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 })
    }

    // FIX: preserve where the user was headed. Previously always redirected
    // to a bare /login with no way to return to the original page after
    // signing in. login/page.tsx (this delivery) reads this and redirects
    // there on successful sign-in instead of hard-coding '/'.
    const url = request.nextUrl.clone()
    url.pathname = '/login'
    url.searchParams.set('next', pathname + request.nextUrl.search)
    return NextResponse.redirect(url)
  }

  // Authenticated user attempting to visit login page
  if (user && isLoginPage) {
    const url = request.nextUrl.clone()
    url.pathname = '/'
    url.search = ''
    return NextResponse.redirect(url)
  }

  return supabaseResponse
}
