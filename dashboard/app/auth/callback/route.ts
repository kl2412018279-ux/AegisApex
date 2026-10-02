// dashboard/app/auth/callback/route.ts
import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url)
  const code = searchParams.get('code')
  const rawNext = searchParams.get('next') ?? '/'

  // FIX: `next` is attacker-controllable (anyone can craft a link to this
  // callback with any ?next= value). Only accept a same-site path starting
  // with a single "/" — this rejects an absolute URL and a protocol-relative
  // "//host" value, either of which could otherwise send a person who just
  // successfully authenticated off to an external site right after.
  const next = rawNext.startsWith('/') && !rawNext.startsWith('//') ? rawNext : '/'

  if (code) {
    const supabase = await createClient()
    const { error } = await supabase.auth.exchangeCodeForSession(code)
    if (!error) {
      // FIX: this was `` `\({origin}\){next}` `` — a broken template
      // literal (the ${...} interpolation had been mangled into \(...\)
      // somewhere between being written and being pasted here, the same
      // corruption pattern seen in a previous useDashboard.ts paste).
      // As written, it would have produced a literal string containing
      // "\(" and "\)" instead of the actual origin and path, sending
      // successful logins to a broken URL.
      return NextResponse.redirect(`${origin}${next}`)
    }
  }

  return NextResponse.redirect(`${origin}/login?error=auth-failed`)
}
