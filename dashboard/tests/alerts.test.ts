import { describe, it, expect, afterEach } from 'vitest';
import { channelWants, envChannels, sendToChannel, type AlertChannel } from '@/lib/alerts';

const channel = (over: Partial<AlertChannel> = {}): AlertChannel => ({
  id: 'c', org_id: 'o', name: 'ops', kind: 'slack', target: 'https://hooks.slack.test/x', min_severity: 'HIGH', events: null, ...over,
});
const event = { kind: 'risk_increase', severity: 'HIGH', title: 'R1 risk rose to HIGH', body: 'from LOW', device_id: 'd1', created_at: '' };

describe('channelWants', () => {
  it('filters by minimum severity', () => {
    expect(channelWants(channel(), { kind: 'risk_increase', severity: 'MEDIUM' })).toBe(false);
    expect(channelWants(channel(), { kind: 'risk_increase', severity: 'CRITICAL' })).toBe(true);
  });
  it('filters by subscribed event kinds', () => {
    expect(channelWants(channel({ events: ['kev_detected'] }), { kind: 'risk_increase', severity: 'CRITICAL' })).toBe(false);
  });
  it('always delivers host key mismatches', () => {
    expect(channelWants(channel({ min_severity: 'CRITICAL' }), { kind: 'host_key_mismatch', severity: 'LOW' })).toBe(true);
  });
  it('respects disabled channels', () => {
    expect(channelWants(channel({ enabled: false }), { kind: 'host_key_mismatch', severity: 'CRITICAL' })).toBe(false);
  });
});

describe('envChannels', () => {
  it('builds channels from env vars', () => {
    const out = envChannels({ ALERT_SLACK_WEBHOOK_URL: 'https://s', ALERT_EMAIL_TO: 'a@b.c', ALERT_MIN_SEVERITY: 'MEDIUM' } as unknown as NodeJS.ProcessEnv);
    expect(out.map((c) => [c.kind, c.min_severity])).toEqual([['slack', 'MEDIUM'], ['email', 'MEDIUM']]);
  });
});

describe('sendToChannel', () => {
  afterEach(() => {
    delete process.env.RESEND_API_KEY;
    delete process.env.ALERT_EMAIL_FROM;
  });

  it('posts Slack blocks', async () => {
    let body: any;
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      body = JSON.parse(String(init.body));
      return new Response('ok');
    }) as unknown as typeof fetch;
    await sendToChannel(channel(), event, fetchImpl);
    expect(body.text).toContain('[HIGH] R1 risk rose to HIGH');
    expect(body.blocks[0].type).toBe('header');
  });

  it('sends email through Resend with attachments', async () => {
    process.env.RESEND_API_KEY = 'k';
    process.env.ALERT_EMAIL_FROM = 'aegis@example.com';
    let url = '';
    let body: any;
    const fetchImpl = (async (u: string, init: RequestInit) => {
      url = u;
      body = JSON.parse(String(init.body));
      return new Response('{}');
    }) as unknown as typeof fetch;
    await sendToChannel(channel({ kind: 'email', target: 'a@x.com, b@x.com' }), event, fetchImpl, [{ filename: 'r.pdf', content: 'AAA' }]);
    expect(url).toBe('https://api.resend.com/emails');
    expect(body.to).toEqual(['a@x.com', 'b@x.com']);
    expect(body.attachments[0].filename).toBe('r.pdf');
  });

  it('throws on a failed delivery so it is recorded', async () => {
    const fetchImpl = (async () => new Response('nope', { status: 500 })) as unknown as typeof fetch;
    await expect(sendToChannel(channel({ kind: 'webhook' }), event, fetchImpl)).rejects.toThrow(/500/);
  });
});
