// dashboard/app/api/update-device-risk/route.ts
// Stores the combined (config + firmware) risk shown in the inventory,
// records it in risk_history and alerts when it goes up.
import { NextRequest, NextResponse } from 'next/server';
import { requireUser, requireDevice } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { RiskBody } from '@/lib/validation';
import { readJson, routeError } from '@/lib/http';
import { riskRank } from '@/lib/risk';
import { recordRisk } from '@/lib/riskHistory';
import { queueAlert } from '@/lib/alerts';

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'operator');
    const { deviceId, riskLevel } = RiskBody.parse(await readJson(req));
    const device = await requireDevice(ctx, deviceId, 'operator');
    const previous = String(device.risk_level || 'UNASSESSED').toUpperCase();

    const { data: updated, error } = await ctx.admin
      .from('devices')
      .update({ risk_level: riskLevel, updated_at: new Date().toISOString() })
      .eq('id', deviceId)
      .select('id, hostname, risk_level')
      .single();
    if (error) throw error;

    if (riskLevel !== 'UNASSESSED') {
      await recordRisk(ctx.admin, { deviceId, riskLevel, source: 'combined' });
      if (riskRank(riskLevel) > riskRank(previous) && riskRank(previous) > 0) {
        await queueAlert(ctx.admin, {
          orgId: device.org_id,
          deviceId,
          kind: 'risk_increase',
          severity: riskLevel as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
          title: `${device.hostname} risk rose from ${previous} to ${riskLevel}`,
          body: 'Open the device in AegisApex to see which findings changed.',
        });
      }
    }
    if (previous !== riskLevel) {
      await audit(ctx, { action: 'device.risk_update', orgId: device.org_id, targetType: 'device', targetId: deviceId, details: { from: previous, to: riskLevel } });
    }

    return NextResponse.json({ success: true, deviceId, riskLevel, device: updated });
  } catch (err) {
    return routeError(err, 'POST /api/update-device-risk');
  }
}
