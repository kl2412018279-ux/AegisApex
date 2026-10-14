// dashboard/app/api/cron/process/route.ts
// Background processing (vercel.json schedules it every 5 minutes):
// change tracking on new snapshots, remediation verification, alert delivery.
import { NextRequest, NextResponse } from 'next/server';
import { requireCron } from '@/lib/auth';
import { routeError } from '@/lib/http';
import { getSupabaseAdmin } from '@/lib/supabase';
import { processNewConfigurations, verifyAppliedRemediations } from '@/lib/processing';
import { dispatchPendingAlerts } from '@/lib/alerts';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(req: NextRequest) {
  try {
    requireCron(req);
    const admin = getSupabaseAdmin();
    const configurationsDiffed = await processNewConfigurations(admin);
    const remediationsVerified = await verifyAppliedRemediations(admin);
    const alerts = await dispatchPendingAlerts(admin);
    const { data: rateLimitRowsPruned } = await admin.rpc('prune_rate_limit_hits');
    return NextResponse.json({ success: true, configurationsDiffed, remediationsVerified, alerts, rateLimitRowsPruned: rateLimitRowsPruned ?? null });
  } catch (err) {
    return routeError(err, 'GET /api/cron/process');
  }
}
