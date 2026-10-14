# AegisApex

Network device security posture for multi-vendor fleets: SSH config and version collection, deterministic CIS checks with compliance mapping, CVE intelligence (NVD + CISA KEV + EPSS), configuration change tracking, alerting, and an approval-gated remediation workflow. An LLM (Groq) writes summaries but never decides a risk rating on its own.

Three parts:

- **`agent/`**: a Python worker that runs inside your network. It SSHes to devices using pinned host keys and talks to Supabase over outbound HTTPS only.
- **`supabase/`**: Postgres with Row Level Security, Vault for device credentials, and Realtime for live updates.
- **`dashboard/`**: a Next.js app and API (Vercel-ready). It handles auth and roles, the rule engine, CVE intelligence, the AI calls, alerts and cron.

The dashboard never connects to devices. It queues jobs in `agent_jobs`; the agent, running somewhere that can reach the devices, picks them up.

## Features

| Area | What it does |
|---|---|
| **Collection** | Agent job queue (`collect` / `remediate` / `rollback`), per-device schedules, SSH host keys pinned on first use and enforced afterwards. Real devices never get synthetic data; only devices flagged `is_mock` do. |
| **Config audit** | 19 CIS rules across 16 platforms, block-aware VTY checks, redacted evidence per finding, mapped to CIS Controls v8, NIST SP 800-53, PCI DSS v4.0 and ISO 27001:2022. |
| **Firmware / CVEs** | NVD lookup by CPE (platform + version), optional Cisco PSIRT openVuln, AI-suggested CVEs only after NVD verification. Every CVE is enriched with CISA KEV (actively exploited) and FIRST EPSS. |
| **Change tracking** | Diffs every new snapshot against the previous one, flags risky changes (telnet enabled, ACL removed, `permit any`, new admin accounts…) and CIS regressions. |
| **Alerts** | Slack, Teams, generic webhook, email (Resend). Per-org channels in the Admin tab or global ones via env vars. |
| **Trends & compliance** | Daily risk history, compliance score per framework, most-failed rules, weekly digest with a PDF attachment. |
| **Remediation** | Operator requests a change, a *different* admin approves, the agent applies it with pre/post snapshots, the CIS rules verify it, one click rolls it back. |
| **Access control** | Organizations with viewer / operator / admin roles, Row Level Security on every table, per-route authorization, audit log, rate-limited AI routes. |

## Setup

### 1. Database

Apply both migrations, in order, to your Supabase project (SQL editor, or `supabase db push`):

```
supabase/migrations/20261014120000_aegisapex_upgrades.sql
supabase/migrations/20261015090000_rate_limits.sql
```

Read its header first. In short:
- Existing devices move into a **Default Organization**, and every existing user becomes its admin.
- Existing RLS policies on `devices`, `configurations`, `scans` and `vulnerabilities` are **replaced**.
- The browser becomes read-only. All writes go through the API.
- Credential columns are hidden from browser roles, and `get_device_credentials` can only be called with the service role.

To test the migration locally against Postgres 16:

```bash
PGHOST=localhost PGUSER=postgres supabase/tests/run.sh
```

### 2. Dashboard

```bash
cd dashboard
cp .env.example .env.local   # fill in Supabase, Groq, CRON_SECRET, alert settings
pnpm install
pnpm dev
```

On Vercel, `dashboard/vercel.json` schedules two cron jobs:
- `/api/cron/process` every 5 minutes: change tracking, remediation verification and alert delivery.
- `/api/cron/digest` on Mondays at 08:00 UTC.

Set `CRON_SECRET` in Vercel. The Hobby plan only allows daily cron jobs. On Hobby, use `.github/workflows/cron.yml` instead: add `APP_BASE_URL` and `CRON_SECRET` as repository secrets and GitHub Actions calls the same endpoints on the same schedule.

### 3. Agent

Run the agent inside the network that can reach your devices:

```bash
cd agent
cp .env.example .env         # SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY
docker build -t aegisapex-agent .
docker run -d --restart unless-stopped --env-file .env aegisapex-agent
```

To run it without Docker: `pip install -r requirements.txt && python worker.py`. To collect every device once: `python collector.py`.

Device credentials stay in Supabase Vault (`get_device_credentials`). The first successful connection pins each device's SSH host key. If the key ever changes, the agent refuses to connect and raises a CRITICAL alert; an admin can reset the pin from the *Changes & Collection* tab. To avoid trusting the first connection, pin keys out of band instead:
1. From a trusted network path, run `python agent/hostkeys.py scan <device-ip>`.
2. Compare the fingerprint it prints with the device console.
3. Paste the key line into *Changes & Collection → Pin a key verified out of band* (admin only).
4. Set `AEGIS_REQUIRE_PINNED_HOST_KEYS=true` on the agent so it refuses any device without a pinned key.

### 4. Users

Users get access through an organization membership. Admins add people from **Admin → Members**, which invites by email if needed.

| Role | Can |
|---|---|
| viewer | read everything in their org |
| operator | + collect, run assessments, simulate changes, request remediations |
| admin | + approve/reject/roll back changes (never their own), reset host keys, manage members and alert channels, read the audit log |

## Development

```bash
cd dashboard && pnpm lint && pnpm typecheck && pnpm test
cd agent && pip install -r requirements-dev.txt && python -m pytest -q tests
```

CI (`.github/workflows/ci.yml`) runs the dashboard checks, the agent tests and the migration/RLS test against Postgres 16.

## Limitations

- **Compliance mappings** are indicative. They only cover what a device configuration can show and are not a formal assessment.
- **CPE names for Huawei, Dell OS10, Nokia SR OS, VyOS and Aruba/Comware** are discovered at runtime: the dashboard tries a short list of candidate names against NVD's CPE dictionary. If NVD has no entry for that exact version, the firmware report says so and relies on NVD-verified AI suggestions.
- **Host key pinning** trusts the first connection unless you pin keys out of band (see *Agent* above) and set `AEGIS_REQUIRE_PINNED_HOST_KEYS=true`.
- **Rate limits** fall back to per-instance memory until the second migration is applied.
