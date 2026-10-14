// dashboard/lib/validation.ts
// Request body schemas. Every route accepts the camelCase field names; the
// snake_case aliases older clients send are mapped onto them first.
import { z } from 'zod';

const MAX_CONFIG_CHARS = 2_000_000;

function camelAliases(input: unknown): unknown {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return input;
  const out: Record<string, unknown> = { ...(input as Record<string, unknown>) };
  for (const [key, value] of Object.entries(out)) {
    if (!key.includes('_')) continue;
    const camel = key.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
    if (out[camel] === undefined) out[camel] = value;
  }
  return out;
}

const body = <T extends z.ZodRawShape>(shape: T) => z.preprocess(camelAliases, z.object(shape));

const uuid = z.string().uuid();
const riskLevel = z.string().transform((v) => v.toUpperCase()).pipe(z.enum(['UNASSESSED', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']));

export const DeviceBody = body({ deviceId: uuid });

export const ScanBody = body({
  deviceId: uuid,
  scanId: uuid.nullish(),
  configurationId: uuid.nullish(),
  vendor: z.string().max(100).optional(),
  rawConfig: z.string().max(MAX_CONFIG_CHARS).optional(),
  rawVersion: z.string().max(200_000).optional(),
});

export const FirmwareBody = body({
  deviceId: uuid,
  vendor: z.string().max(100).optional(),
  rawVersion: z.string().max(200_000).optional(),
});

export const ImpactBody = body({
  deviceId: z.preprocess((v) => (v === '' ? undefined : v), uuid.optional()),
  vendor: z.string().max(100).optional(),
  activeConfig: z.string().max(MAX_CONFIG_CHARS).optional(),
  proposedCommand: z.string().min(1).max(20_000),
});

export const RiskBody = body({ deviceId: uuid, riskLevel });

export const RemediationCreateBody = body({
  deviceId: uuid,
  title: z.string().min(1).max(300),
  commands: z.string().min(1).max(20_000),
  rollbackCommands: z.string().max(20_000).optional(),
  ruleId: z.string().max(50).optional(),
});

export const RemediationDecisionBody = body({ note: z.string().max(2000).optional() });

export const AlertChannelBody = body({
  orgId: uuid,
  name: z.string().min(1).max(100),
  kind: z.enum(['slack', 'teams', 'webhook', 'email']),
  target: z.string().min(3).max(2000),
  minSeverity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('HIGH'),
  events: z.array(z.string().max(50)).max(20).optional(),
}).superRefine((v, ctx) => {
  if (v.kind === 'email' ? !/^[^@\s]+@[^@\s]+$/.test(v.target) : !/^https:\/\//.test(v.target)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['target'], message: v.kind === 'email' ? 'must be an email address' : 'must be an https:// URL' });
  }
});

export const MemberBody = body({
  orgId: uuid,
  email: z.string().email(),
  role: z.enum(['viewer', 'operator', 'admin']),
});

export const DeviceSettingsBody = body({
  deviceId: uuid,
  collectionIntervalMinutes: z.number().int().min(5).max(10_080).optional(),
  isMock: z.boolean().optional(),
  resetHostKey: z.boolean().optional(),
  /** Public host key verified out of band, e.g. a line of ssh-keyscan output. */
  pinHostKey: z.string().min(20).max(4000).optional(),
});
