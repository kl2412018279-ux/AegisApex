// dashboard/lib/alerts.ts
// Alerts are written to alert_events (by the dashboard or the agent) and
// delivered by dispatchPendingAlerts(), which /api/cron/process runs. One
// delivery path means one place to retry, rate-limit and audit.
import type { SupabaseClient } from '@supabase/supabase-js';
import { riskRank } from './risk';

export type AlertKind =
  | 'risk_increase'
  | 'risky_change'
  | 'kev_detected'
  | 'device_unreachable'
  | 'host_key_mismatch'
  | 'remediation_pending'
  | 'remediation_result'
  | 'weekly_digest';

export interface AlertInput {
  orgId: string | null;
  deviceId?: string | null;
  kind: AlertKind;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  body?: string;
}

export interface AlertChannel {
  id: string;
  org_id: string | null;
  name: string;
  kind: 'slack' | 'teams' | 'webhook' | 'email';
  target: string;
  min_severity: string;
  events: string[] | null;
  enabled?: boolean;
}

export interface Attachment {
  filename: string;
  /** base64 */
  content: string;
}

interface AlertEventRow {
  id: string;
  org_id: string | null;
  device_id: string | null;
  kind: string;
  severity: string;
  title: string;
  body: string | null;
  created_at: string;
}

// Host key mismatches can mean an active attack: always delivered.
const ALWAYS_DELIVER = new Set(['host_key_mismatch']);

export async function queueAlert(admin: SupabaseClient, alert: AlertInput): Promise<void> {
  const { error } = await admin.from('alert_events').insert({
    org_id: alert.orgId,
    device_id: alert.deviceId ?? null,
    kind: alert.kind,
    severity: alert.severity,
    title: alert.title,
    body: alert.body ?? null,
  });
  if (error) console.error('[-] Failed to queue alert:', error.message);
}

/** Channels defined by env vars apply to every organization. */
export function envChannels(env: NodeJS.ProcessEnv = process.env): AlertChannel[] {
  const min = env.ALERT_MIN_SEVERITY || 'HIGH';
  const channels: AlertChannel[] = [];
  const add = (kind: AlertChannel['kind'], target: string | undefined) => {
    if (target) channels.push({ id: `env-${kind}`, org_id: null, name: `${kind} (env)`, kind, target, min_severity: min, events: null });
  };
  add('slack', env.ALERT_SLACK_WEBHOOK_URL);
  add('teams', env.ALERT_TEAMS_WEBHOOK_URL);
  add('webhook', env.ALERT_WEBHOOK_URL);
  add('email', env.ALERT_EMAIL_TO);
  return channels;
}

export function channelWants(channel: AlertChannel, event: Pick<AlertEventRow, 'kind' | 'severity'>): boolean {
  if (channel.enabled === false) return false;
  if (channel.events && channel.events.length > 0 && !channel.events.includes(event.kind)) return false;
  if (ALWAYS_DELIVER.has(event.kind) || event.kind === 'weekly_digest') return true;
  return riskRank(event.severity) >= riskRank(channel.min_severity);
}

const SEVERITY_EMOJI: Record<string, string> = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };

function appLink(event: Pick<AlertEventRow, 'device_id'>): string {
  const base = process.env.APP_BASE_URL;
  if (!base) return '';
  return event.device_id ? `${base}/?device=${event.device_id}` : base;
}

export async function sendToChannel(
  channel: AlertChannel,
  event: Pick<AlertEventRow, 'kind' | 'severity' | 'title' | 'body' | 'device_id' | 'created_at'>,
  fetchImpl: typeof fetch = fetch,
  attachments: Attachment[] = []
): Promise<void> {
  const heading = `${SEVERITY_EMOJI[event.severity] || '⚪'} [${event.severity}] ${event.title}`;
  const link = appLink(event);
  const text = [heading, event.body || '', link].filter(Boolean).join('\n\n');

  let res: Response;
  if (channel.kind === 'slack') {
    res = await fetchImpl(channel.target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: heading,
        blocks: [
          { type: 'header', text: { type: 'plain_text', text: heading.slice(0, 150) } },
          ...(event.body ? [{ type: 'section', text: { type: 'mrkdwn', text: event.body.slice(0, 2900) } }] : []),
          ...(link ? [{ type: 'context', elements: [{ type: 'mrkdwn', text: `<${link}|Open in AegisApex>` }] }] : []),
        ],
      }),
    });
  } else if (channel.kind === 'teams') {
    res = await fetchImpl(channel.target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text.replace(/\n/g, '<br>') }),
    });
  } else if (channel.kind === 'webhook') {
    res = await fetchImpl(channel.target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'aegisapex', ...event, link: link || null }),
    });
  } else {
    const apiKey = process.env.RESEND_API_KEY;
    const from = process.env.ALERT_EMAIL_FROM;
    if (!apiKey || !from) throw new Error('Email channel needs RESEND_API_KEY and ALERT_EMAIL_FROM');
    res = await fetchImpl('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from,
        to: channel.target.split(',').map((s) => s.trim()),
        subject: `[AegisApex] ${heading}`,
        text,
        ...(attachments.length ? { attachments } : {}),
      }),
    });
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`${channel.kind} returned ${res.status}: ${detail.slice(0, 200)}`);
  }
}

export interface DispatchSummary {
  processed: number;
  sent: number;
  failed: number;
  suppressed: number;
}

export async function dispatchPendingAlerts(
  admin: SupabaseClient,
  fetchImpl: typeof fetch = fetch,
  limit = 50
): Promise<DispatchSummary> {
  const summary: DispatchSummary = { processed: 0, sent: 0, failed: 0, suppressed: 0 };
  const { data: events, error } = await admin
    .from('alert_events')
    .select('*')
    .eq('status', 'pending')
    .order('created_at', { ascending: true })
    .limit(limit);
  if (error) throw error;
  if (!events || events.length === 0) return summary;

  const { data: orgChannels } = await admin.from('alert_channels').select('*').eq('enabled', true);
  const globalChannels = envChannels();

  for (const event of events as AlertEventRow[]) {
    summary.processed++;
    const candidates = [...globalChannels, ...((orgChannels || []) as AlertChannel[]).filter((c) => c.org_id === event.org_id)];
    const targets = candidates.filter((c) => channelWants(c, event));
    if (targets.length === 0) {
      summary.suppressed++;
      await admin.from('alert_events').update({ status: 'suppressed', sent_at: new Date().toISOString() }).eq('id', event.id);
      continue;
    }

    const delivered: Record<string, string> = {};
    let anyOk = false;
    for (const channel of targets) {
      try {
        await sendToChannel(channel, event, fetchImpl);
        delivered[channel.name] = 'ok';
        anyOk = true;
      } catch (err) {
        delivered[channel.name] = err instanceof Error ? err.message : String(err);
      }
    }
    if (anyOk) summary.sent++;
    else summary.failed++;
    await admin
      .from('alert_events')
      .update({ status: anyOk ? 'sent' : 'failed', delivered, sent_at: new Date().toISOString() })
      .eq('id', event.id);
  }
  return summary;
}
