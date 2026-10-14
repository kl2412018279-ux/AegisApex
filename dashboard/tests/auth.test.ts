import { describe, it, expect, vi, beforeEach } from 'vitest';

// In-memory stand-ins for the session client and the service-role client.
const state: { user: { id: string; email: string } | null; members: Array<{ org_id: string; role: string }>; devices: Record<string, any> } = {
  user: null,
  members: [],
  devices: {},
};

vi.mock('@/lib/supabase/server', () => ({
  createClient: async () => ({ auth: { getUser: async () => ({ data: { user: state.user }, error: null }) } }),
}));

function table(name: string) {
  const filters: Record<string, unknown> = {};
  const q: any = {
    select: () => q,
    eq: (col: string, val: unknown) => ((filters[col] = val), q),
    insert: async () => ({ error: null }),
    then: (resolve: (v: unknown) => void) => resolve({ data: name === 'org_members' ? state.members : [], error: null }),
    maybeSingle: async () => ({ data: name === 'devices' ? state.devices[filters.id as string] ?? null : null, error: null }),
  };
  return q;
}
vi.mock('@/lib/supabase', () => ({ getSupabaseAdmin: () => ({ from: table }) }));

import { requireUser, requireDevice, requireCron } from '@/lib/auth';
import { HttpError } from '@/lib/http';
import { POST as updateRisk } from '@/app/api/update-device-risk/route';

const req = (body?: unknown, headers: Record<string, string> = {}) =>
  new Request('http://localhost/api/x', { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: body ? JSON.stringify(body) : undefined });

const ORG_A = '00000000-0000-0000-0000-00000000000a';
const ORG_B = '00000000-0000-0000-0000-00000000000b';
const DEV_B = '11111111-1111-1111-1111-11111111111b';

beforeEach(() => {
  state.user = { id: 'u1', email: 'u1@example.com' };
  state.members = [{ org_id: ORG_A, role: 'viewer' }];
  state.devices = { [DEV_B]: { id: DEV_B, org_id: ORG_B, hostname: 'B1' } };
});

describe('requireUser', () => {
  it('rejects requests without a session', async () => {
    state.user = null;
    await expect(requireUser(req())).rejects.toMatchObject({ status: 401 });
  });

  it('rejects users without the required role', async () => {
    await expect(requireUser(req(), 'operator')).rejects.toMatchObject({ status: 403 });
  });

  it('accepts users with the role in any org', async () => {
    state.members.push({ org_id: ORG_B, role: 'admin' });
    const ctx = await requireUser(req(), 'admin');
    expect(ctx.memberships).toHaveLength(2);
  });
});

describe('requireDevice', () => {
  it('hides devices from other organizations as 404', async () => {
    const ctx = await requireUser(req());
    await expect(requireDevice(ctx, DEV_B, 'viewer')).rejects.toMatchObject({ status: 404 });
  });

  it('enforces the role within the device\'s own organization', async () => {
    state.members = [{ org_id: ORG_A, role: 'admin' }, { org_id: ORG_B, role: 'viewer' }];
    const ctx = await requireUser(req());
    await expect(requireDevice(ctx, DEV_B, 'operator')).rejects.toMatchObject({ status: 403 });
    await expect(requireDevice(ctx, DEV_B, 'viewer')).resolves.toMatchObject({ hostname: 'B1' });
  });
});

describe('requireCron', () => {
  it('requires the bearer secret', () => {
    process.env.CRON_SECRET = 's3cret';
    expect(() => requireCron(req(undefined, { authorization: 'Bearer nope' }))).toThrow(HttpError);
    expect(() => requireCron(req(undefined, { authorization: 'Bearer s3cret' }))).not.toThrow();
  });
});

describe('route integration', () => {
  it('returns 401 JSON when signed out', async () => {
    state.user = null;
    const res = await updateRisk(req({ deviceId: DEV_B, riskLevel: 'HIGH' }) as any);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ success: false, error: 'Unauthorized' });
  });

  it('returns 400 for an invalid body', async () => {
    state.members = [{ org_id: ORG_B, role: 'operator' }];
    const res = await updateRisk(req({ deviceId: 'not-a-uuid', riskLevel: 'HIGH' }) as any);
    expect(res.status).toBe(400);
  });

  it('returns 403 for a viewer', async () => {
    state.members = [{ org_id: ORG_B, role: 'viewer' }];
    const res = await updateRisk(req({ deviceId: DEV_B, riskLevel: 'HIGH' }) as any);
    expect(res.status).toBe(403);
  });
});
