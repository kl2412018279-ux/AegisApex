// dashboard/app/reset-password/page.tsx
//
// New. Landed on after /auth/callback exchanges a password-recovery code
// for a session. At that point the user has a valid (recovery-scoped)
// session, so supabase.auth.updateUser({ password }) is enough — no old
// password needed, which is normal and correct for a "forgot password"
// flow specifically (as opposed to a "change password while logged in"
// flow, which should ask for the current password too).
'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';
import { ShieldCheck, Loader2, Eye, EyeOff } from 'lucide-react';

export default function ResetPasswordPage() {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const router = useRouter();
  const supabase = createClient();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    const { error: updateError } = await supabase.auth.updateUser({ password });
    setLoading(false);

    if (updateError) {
      setError(updateError.message);
      return;
    }

    router.push('/login?reset=success');
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-12 text-slate-100">
      <div className="w-full max-w-md space-y-8 rounded-xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl backdrop-blur-md">
        <div className="text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-600/20 text-emerald-400">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <h2 className="mt-4 text-2xl font-bold tracking-tight text-white">Set a new password</h2>
        </div>

        {error && (
          <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-400">
            {error}
          </div>
        )}

        <form className="mt-6 space-y-4" onSubmit={handleSubmit} noValidate>
          <div>
            <label htmlFor="password" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
              New Password
            </label>
            <div className="relative mt-1">
              <input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                required
                minLength={8}
                autoComplete="new-password"
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="At least 8 characters"
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

          <div>
            <label htmlFor="confirmPassword" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
              Confirm New Password
            </label>
            <input
              id="confirmPassword"
              name="confirmPassword"
              type={showPassword ? 'text' : 'password'}
              required
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Repeat password"
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading && <Loader2 className="h-4 w-4 animate-spin" />}
            {loading ? 'Saving…' : 'Update password'}
          </button>
        </form>
      </div>
    </div>
  );
}

