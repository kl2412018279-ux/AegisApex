// dashboard/app/api/trigger-collection/route.ts
// Queues an SSH collection for the agent (agent/worker.py), which runs
// inside the network and picks the job up from agent_jobs. The dashboard
// never SSHes to devices itself, so it can run on Vercel.
//
// Real devices are never given synthetic data. If the agent can't reach a
// device the job fails, the device is marked unreachable and an alert is
// raised. Only devices flagged is_mock get generated demo telemetry.
import { NextRequest, NextResponse } from 'next/server';
import { requireUser, requireDevice } from '@/lib/auth';
import { audit } from '@/lib/audit';
import { DeviceBody } from '@/lib/validation';
import { readJson, routeError, HttpError } from '@/lib/http';
import { enqueueJob, collectMockDevice } from '@/lib/collection';

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireUser(req, 'operator');
    const { deviceId } = DeviceBody.parse(await readJson(req));
    const device = await requireDevice(ctx, deviceId, 'operator');

    if (device.is_mock) {
      const { configurationId } = await collectMockDevice(ctx.admin, device);
      await audit(ctx, { action: 'collect.mock', orgId: device.org_id, targetType: 'device', targetId: deviceId });
      return NextResponse.json({
        success: true,
        mode: 'synthetic',
        message: `SYNTHETIC demo telemetry generated for ${device.hostname} (device is flagged as a mock).`,
        deviceId,
        configurationId,
      });
    }

    if (!device.management_ip && !device.ip_address) {
      throw new HttpError(422, `${device.hostname} has no management IP configured. Set one before collecting telemetry.`);
    }

    const job = await enqueueJob(ctx.admin, deviceId, 'collect', ctx.userId);
    await audit(ctx, { action: 'collect.queued', orgId: device.org_id, targetType: 'device', targetId: deviceId, details: { jobId: job.id } });
    return NextResponse.json({
      success: true,
      mode: 'queued',
      message: `Collection queued for ${device.hostname}. The AegisApex agent will pick it up.`,
      deviceId,
      jobId: job.id,
      jobStatus: job.status,
    });
  } catch (err) {
    return routeError(err, 'POST /api/trigger-collection');
  }
}
