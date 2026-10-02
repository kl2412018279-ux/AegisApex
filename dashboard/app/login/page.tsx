// C:\Users\hp\aiops-securewatch\dashboard\app\login\page.tsx
// dashboard/app/login/page.tsx
//
// Rewritten from the version you added, which built the whole page with
// React.createElement() instead of JSX — no functional reason to do that
// in a .tsx file, just harder to read and edit. This is plain JSX.
//
// FIX: `next` is preserved through the flow. Your original hard-coded
// router.push('/') after a successful login, so if the auth middleware
// redirected someone here from a deep link (e.g. they had /?tab=sandbox
// open in a tab that expired), a successful login always dropped them on
// the root page instead of back where they were headed. Now reads
// ?next=... from the URL (set by middleware.ts, added in this delivery)
// and returns there after sign-in.
//
// DELIBERATE: no "create account" / sign-up link. You said this is for one
// dedicated entity with no role system — a public self-registration link
// on a device-audit tool's login page would let a stranger create an
// account for themselves if email signups are enabled on your Supabase
// project. Create the one account you need directly in the Supabase
// dashboard (Authentication > Users > Add user) instead. If your Supabase
// project currently has "Allow new users to sign up" turned on, turn it
// off (Authentication > Providers > Email) — that setting matters more
// than anything on this page, since it controls whether an API call to
// supabase.auth.signUp() from outside this UI could create an account
// regardless of what links this page does or doesn't show.
//
// BUILD FIX: useSearchParams() must be called inside a component that is
// wrapped in <Suspense>, or `next build` fails trying to statically
// prerender this page ("useSearchParams() should be wrapped in a suspense
// boundary"). The actual form + all its logic now lives in LoginForm;
// LoginPage just wraps it in Suspense.
'use client';

import React, { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';
import { Eye, EyeOff, ShieldCheck, Loader2 } from 'lucide-react';

function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const router = useRouter();
  const searchParams = useSearchParams();
  const supabase = createClient();

  // FIX: safe redirect target only. `next` comes from the URL, which is
  // attacker-controllable (anyone can send someone a link with any ?next=
  // value). Only accept a same-site path starting with a single "/" —
  // reject absolute URLs and protocol-relative "//host" values, which
  // would otherwise let a crafted link send a successfully-authenticated
  // user off to an external site right after they prove who they are.
  const rawNext = searchParams.get('next') || '/';
  const next = rawNext.startsWith('/') && !rawNext.startsWith('//') ? rawNext : '/';

  const authErrorFailed = searchParams.get('error') === 'auth-failed';

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const { error: signInError } = await supabase.auth.signInWithPassword({
        email: email.trim(),
        password,
      });

      if (signInError) {
        // Supabase returns the same generic message for "no such user" and
        // "wrong password" by design (doesn't confirm which emails have
        // accounts) — surfaced as-is rather than rewritten, so we don't
        // accidentally leak more than Supabase intends to.
        setError(signInError.message || 'Invalid email or password.');
        setLoading(false);
        return;
      }

      router.push(next);
      router.refresh();
    } catch (err: any) {
      setError(err?.message || 'An unexpected authentication error occurred.');
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-12 text-slate-100">
      <div className="w-full max-w-md space-y-8 rounded-xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl backdrop-blur-md">
        <div className="text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-600/20 text-emerald-400">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <h2 className="mt-4 text-2xl font-bold tracking-tight text-white">AegisApex</h2>
          <p className="mt-1 text-sm text-slate-400">
            Sign in to access network telemetry & security audits
          </p>
        </div>

        {authErrorFailed && (
          <div
            role="alert"
            className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-300"
          >
            Your sign-in link could not be verified. Please sign in again.
          </div>
        )}

        {error && (
          <div
            role="alert"
            aria-live="polite"
            className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-400"
          >
            {error}
          </div>
        )}

        <form className="mt-6 space-y-4" onSubmit={handleLogin} noValidate>
          <div>
            <label
              htmlFor="email"
              className="block text-xs font-medium uppercase tracking-wider text-slate-300"
            >
              Email Address
            </label>
            <input
              id="email"
              name="email"
              type="email"
              required
              autoComplete="email"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
          </div>

          <div>
            <div className="flex items-center justify-between">
              <label
                htmlFor="password"
                className="block text-xs font-medium uppercase tracking-wider text-slate-300"
              >
                Password
              </label>
              <a
                href="/forgot-password"
                className="text-xs font-medium text-emerald-400 hover:text-emerald-300"
              >
                Forgot password?
              </a>
            </div>
            <div className="relative mt-1">
              <input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 pr-10 text-sm text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                tabIndex={-1}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                className="absolute inset-y-0 right-0 flex items-center px-3 text-slate-500 hover:text-slate-300"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading && <Loader2 className="h-4 w-4 animate-spin" />}
            {loading ? 'Authenticating…' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}