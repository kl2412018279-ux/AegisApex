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
  // Cron routes have no user session; they authenticate with CRON_SECRET
  // inside the handler (lib/auth.ts requireCron).
  const isCronRoute = pathname.startsWith('/api/cron/')
  const isPublicAuthPage =
    isLoginPage || isAuthCallback || isCronRoute || pathname.startsWith('/forgot-password') || pathname.startsWith('/reset-password')

  // Unauthenticated request to anything else
  if (!user && !isPublicAuthPage) {
    // fetch() callers need JSON, not a redirect to the login page.
    if (isApiRoute) {
      return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 })
    }

    // Return the user to where they were headed after signing in.
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
