// dashboard/app/forgot-password/page.tsx
//
// New. The login page links to /forgot-password — this is that page.
// Sends a Supabase password-recovery email; the link in that email lands
// on /auth/callback (which exchanges the recovery code for a session) and
// then redirects to /reset-password to actually set a new password.
'use client';

import React, { useState } from 'react';
import { createClient } from '@/lib/supabase/client';
import { ShieldCheck, Loader2 } from 'lucide-react';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [sent, setSent] = useState(false);

  const supabase = createClient();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const { error: resetError } = await supabase.auth.resetPasswordForEmail(email.trim(), {
      redirectTo: `${window.location.origin}/auth/callback?next=/reset-password`,
    });

    setLoading(false);

    // Always show the same "check your email" state whether or not the
    // address exists — resetPasswordForEmail does not error on an unknown
    // address by design (Supabase avoids confirming which emails have
    // accounts), so there's nothing meaningful to branch on here anyway.
    if (resetError) {
      setError(resetError.message);
    } else {
      setSent(true);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-12 text-slate-100">
      <div className="w-full max-w-md space-y-8 rounded-xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl backdrop-blur-md">
        <div className="text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-600/20 text-emerald-400">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <h2 className="mt-4 text-2xl font-bold tracking-tight text-white">Reset your password</h2>
          <p className="mt-1 text-sm text-slate-400">
            {sent
              ? "If that email has an account, we've sent a reset link."
              : "Enter your email and we'll send you a reset link."}
          </p>
        </div>

        {error && (
          <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-400">
            {error}
          </div>
        )}

        {!sent ? (
          <form className="mt-6 space-y-4" onSubmit={handleSubmit} noValidate>
            <div>
              <label htmlFor="email" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
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

            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? 'Sending…' : 'Send reset link'}
            </button>
          </form>
        ) : null}

        <div className="text-center">
          <a href="/login" className="text-xs font-medium text-slate-400 hover:text-slate-200">
            &larr; Back to sign in
          </a>
        </div>
      </div>
    </div>
  );
}
