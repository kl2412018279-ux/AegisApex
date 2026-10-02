// dashboard/_hooks/useAuth.ts
//
// NEW FILE. Header.tsx already renders a "Sign Out" button and accepts an
// `onSignOut?: () => void` prop, but nothing in the files reviewed so far
// actually provides that function — so the button was (or would be, once
// wired) either missing its handler or a no-op. This hook is the handler.
//
// Wire it into your page (wherever <Header /> is rendered, likely
// app/page.tsx) like:
//
//   import { useAuth } from './_hooks/useAuth';
//   const { signOut } = useAuth();
//   ...
//   <Header ... onSignOut={signOut} />
//
'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

export function useAuth() {
  const [signingOut, setSigningOut] = useState(false);
  const router = useRouter();
  const supabase = createClient();

  const signOut = useCallback(async () => {
    setSigningOut(true);
    try {
      await supabase.auth.signOut();
    } finally {
      // Regardless of whether signOut() itself errored, send the user to
      // /login and refresh so middleware re-evaluates the (now cleared)
      // session — router.refresh() alone wouldn't be enough if they're
      // sitting on a page middleware would otherwise let a stale client
      // render for a moment.
      router.push('/login');
      router.refresh();
      setSigningOut(false);
    }
  }, [router, supabase]);

  return { signOut, signingOut };
}
