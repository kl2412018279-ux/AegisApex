// dashboard/lib/collection.ts
import type { SupabaseClient } from '@supabase/supabase-js';
import { generateVendorConfig, generateVendorVersion } from './vendor-telemetry';

export type JobKind = 'collect' | 'remediate' | 'rollback';

export interface QueuedJob {
  id: string;
  status: string;
  kind: JobKind;
}

/**
 * Adds a job to the agent queue. A device never has two collect jobs
 * waiting at once; asking again returns the job already queued.
 */
export async function enqueueJob(
  admin: SupabaseClient,
  deviceId: string,
  kind: JobKind,
  requestedBy: string | null,
  payload: Record<string, unknown> = {}
): Promise<QueuedJob> {
  if (kind === 'collect') {
    const { data: active } = await admin
      .from('agent_jobs')
      .select('id, status, kind')
      .eq('device_id', deviceId)
      .eq('kind', 'collect')
      .in('status', ['queued', 'running'])
      .limit(1)
      .maybeSingle();
    if (active) return active as QueuedJob;
  }
  const { data, error } = await admin
    .from('agent_jobs')
    .insert({ device_id: deviceId, kind, payload, requested_by: requestedBy })
    .select('id, status, kind')
    .single();
  if (error) throw error;
  return data as QueuedJob;
}

/** Demo devices only (devices.is_mock). Stored with source = 'synthetic'. */
export async function collectMockDevice(
  admin: SupabaseClient,
  device: { id: string; hostname?: string; vendor?: string; netmiko_type?: string }
): Promise<{ configurationId: string }> {
  const vendor = device.netmiko_type || device.vendor || 'cisco_ios';
  const rawConfig = generateVendorConfig(device.hostname || 'demo-device', vendor);
  const rawVersion = generateVendorVersion(device.hostname || 'demo-device', vendor);
  const now = new Date().toISOString();

  const { data: config, error } = await admin
    .from('configurations')
    .insert({ device_id: device.id, raw_config: rawConfig, content: rawConfig, source: 'synthetic', created_at: now })
    .select('id')
    .single();
  if (error) throw error;

  await admin.from('scans').insert({
    device_id: device.id,
    configuration_id: config.id,
    raw_version: rawVersion,
    risk_level: 'UNASSESSED',
    summary: 'SYNTHETIC demo telemetry (this device is flagged as a mock). Run AI Assessment to analyze it.',
    model_used: 'synthetic-demo',
    created_at: now,
  });
  await admin
    .from('devices')
    .update({ connection_status: 'online', last_seen_at: now, last_config: rawConfig, raw_version: rawVersion })
    .eq('id', device.id);

  return { configurationId: config.id };
}
