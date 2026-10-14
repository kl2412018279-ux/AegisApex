// dashboard/app/api/cron/digest/route.ts
// Weekly digest to every channel subscribed to "weekly_digest".
import { NextRequest, NextResponse } from 'next/server';
import { requireCron } from '@/lib/auth';
import { routeError } from '@/lib/http';
import { getSupabaseAdmin } from '@/lib/supabase';
import { sendDigests } from '@/lib/digest';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(req: NextRequest) {
  try {
    requireCron(req);
    return NextResponse.json({ success: true, results: await sendDigests(getSupabaseAdmin()) });
  } catch (err) {
    return routeError(err, 'GET /api/cron/digest');
  }
}
