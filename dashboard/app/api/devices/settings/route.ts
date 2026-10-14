// dashboard/app/api/devices/settings/route.ts
// Per-device collection schedule, mock flag, and SSH host key reset.
import { NextRequest, NextResponse } from 'next/server';
import { requireUser, requireDevice, roleAtLeast, roleInOrg } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { DeviceSettingsBody } from '@/lib/validation';
import { readJson, routeError, HttpError } from '@/lib/http';

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'operator');
    const body = DeviceSettingsBody.parse(await readJson(req));
    const device = await requireDevice(ctx, body.deviceId, 'operator');
    const update: Record<string, unknown> = {};

    if (body.collectionIntervalMinutes !== undefined) {
      update.collection_interval_minutes = body.collectionIntervalMinutes;
      update.next_collection_at = new Date(Date.now() + body.collectionIntervalMinutes * 60_000).toISOString();
    }
    if (body.isMock !== undefined) update.is_mock = body.isMock;
    if (body.resetHostKey) {
      // Accepting a new host key is a trust decision: admins only.
      if (!roleAtLeast(roleInOrg(ctx, device.org_id), 'admin')) throw new HttpError(403, 'Only an admin can reset a pinned SSH host key.');
      Object.assign(update, { ssh_host_key: null, ssh_host_key_type: null, ssh_host_key_fingerprint: null, ssh_host_key_pinned_at: null });
    }
    if (!Object.keys(update).length) throw new HttpError(400, 'Nothing to update.');

    const { data, error } = await ctx.admin
      .from('devices')
      .update({ ...update, updated_at: new Date().toISOString() })
      .eq('id', device.id)
      .select('id, collection_interval_minutes, next_collection_at, is_mock, ssh_host_key_fingerprint')
      .single();
    if (error) throw error;

    await audit(ctx, {
      action: body.resetHostKey ? 'device.host_key_reset' : 'device.settings',
      orgId: device.org_id,
      targetType: 'device',
      targetId: device.id,
      details: { ...body, previousFingerprint: body.resetHostKey ? device.ssh_host_key_fingerprint : undefined },
    });
    return NextResponse.json({ success: true, device: data });
  } catch (err) {
    return routeError(err, 'POST /api/devices/settings');
  }
}
