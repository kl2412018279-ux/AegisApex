-- AegisApex upgrade migration
--
-- Adds: organizations + roles, Row Level Security on every table, an audit
-- log, the agent job queue, risk history, config change tracking, alerting,
-- and the remediation approval workflow.
--
-- Safe to re-run. Apply with `supabase db push` or paste into the SQL editor.
--
-- READ BEFORE APPLYING
--  * Existing devices are assigned to a "Default Organization" and every
--    existing auth user becomes an admin of it, so nobody is locked out.
--    Users created AFTER this migration see nothing until an admin adds them
--    (Admin tab in the dashboard, or insert into org_members).
--  * Existing RLS policies on devices / configurations / scans /
--    vulnerabilities are DROPPED and replaced. Any permissive policy left in
--    place would OR with these and re-open the data.
--  * The browser can only SELECT. All writes go through the Next.js API
--    (service role), which enforces roles and writes the audit log.
--  * Credential columns on devices (ssh_pass, enable_pass, ...) are hidden
--    from browser roles via column grants. New devices columns added later
--    must be granted explicitly (see the grant block near the end).

create extension if not exists pgcrypto;

-- ─── Organizations & membership ────────────────────────────────────────────

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.org_members (
  org_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('viewer', 'operator', 'admin')),
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);
create index if not exists org_members_user_idx on public.org_members(user_id);

insert into public.organizations (id, name)
values ('00000000-0000-0000-0000-000000000001', 'Default Organization')
on conflict (id) do nothing;

-- ─── Columns on existing tables ────────────────────────────────────────────

alter table public.devices add column if not exists org_id uuid references public.organizations(id);
alter table public.devices add column if not exists is_mock boolean not null default false;
alter table public.devices add column if not exists ssh_port integer;
alter table public.devices add column if not exists ssh_host_key_type text;
alter table public.devices add column if not exists ssh_host_key text;
alter table public.devices add column if not exists ssh_host_key_fingerprint text;
alter table public.devices add column if not exists ssh_host_key_pinned_at timestamptz;
alter table public.devices add column if not exists collection_interval_minutes integer not null default 60;
alter table public.devices add column if not exists next_collection_at timestamptz;
alter table public.devices add column if not exists last_collection_error text;
alter table public.devices add column if not exists updated_at timestamptz;

update public.devices set org_id = '00000000-0000-0000-0000-000000000001' where org_id is null;

alter table public.configurations add column if not exists source text not null default 'ssh';
alter table public.configurations add column if not exists drift_checked_at timestamptz;
do $$ begin
  alter table public.configurations add constraint configurations_source_check
    check (source in ('ssh', 'synthetic', 'manual', 'post_remediation'));
exception when duplicate_object then null; end $$;

alter table public.scans add column if not exists rules_evaluated integer;
alter table public.scans add column if not exists cve_details jsonb;

alter table public.vulnerabilities add column if not exists rule_id text;
alter table public.vulnerabilities add column if not exists evidence text;
alter table public.vulnerabilities add column if not exists frameworks jsonb;

insert into public.org_members (org_id, user_id, role)
select '00000000-0000-0000-0000-000000000001', id, 'admin' from auth.users
on conflict do nothing;

-- ─── Agent job queue ───────────────────────────────────────────────────────

create table if not exists public.agent_jobs (
  id uuid primary key default gen_random_uuid(),
  device_id uuid not null references public.devices(id) on delete cascade,
  kind text not null check (kind in ('collect', 'remediate', 'rollback')),
  status text not null default 'queued'
    check (status in ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  payload jsonb not null default '{}'::jsonb,
  result jsonb,
  error text,
  requested_by uuid references auth.users(id),
  worker text,
  attempts integer not null default 0,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz
);
create index if not exists agent_jobs_queue_idx on public.agent_jobs(status, created_at);
create index if not exists agent_jobs_device_idx on public.agent_jobs(device_id, created_at desc);

-- Atomically hands the oldest queued job to one worker.
create or replace function public.claim_agent_job(p_worker text)
returns setof public.agent_jobs
language plpgsql security definer set search_path = public as $$
begin
  return query
  update public.agent_jobs j
     set status = 'running', started_at = now(), worker = p_worker, attempts = j.attempts + 1
   where j.id = (
     select id from public.agent_jobs
      where status = 'queued'
      order by created_at
      for update skip locked
      limit 1)
  returning j.*;
end $$;

-- Queues a collect job for every device whose schedule is due, and fails
-- jobs a crashed worker left in "running".
create or replace function public.enqueue_due_collections()
returns integer
language plpgsql security definer set search_path = public as $$
declare
  n integer;
begin
  update public.agent_jobs
     set status = 'failed', error = 'Worker did not finish within 30 minutes', finished_at = now()
   where status = 'running' and started_at < now() - interval '30 minutes';

  with due as (
    select d.id from public.devices d
     where not d.is_mock
       and d.connection_status is distinct from 'inactive'
       and coalesce(d.next_collection_at, '-infinity'::timestamptz) <= now()
       and not exists (
         select 1 from public.agent_jobs j
          where j.device_id = d.id and j.kind = 'collect' and j.status in ('queued', 'running'))
     for update skip locked
  ), queued as (
    insert into public.agent_jobs (device_id, kind)
    select id, 'collect' from due
    returning device_id
  )
  update public.devices d
     set next_collection_at = now() + make_interval(mins => greatest(d.collection_interval_minutes, 5))
   where d.id in (select device_id from queued);

  get diagnostics n = row_count;
  return n;
end $$;

revoke all on function public.claim_agent_job(text) from public, anon, authenticated;
revoke all on function public.enqueue_due_collections() from public, anon, authenticated;
grant execute on function public.claim_agent_job(text) to service_role;
grant execute on function public.enqueue_due_collections() to service_role;

-- ─── Risk history, change tracking ─────────────────────────────────────────

create table if not exists public.risk_history (
  id bigserial primary key,
  device_id uuid not null references public.devices(id) on delete cascade,
  risk_level text not null,
  source text not null check (source in ('config', 'firmware', 'combined')),
  findings_count integer,
  rules_evaluated integer,
  cve_count integer,
  kev_count integer,
  recorded_at timestamptz not null default now()
);
create index if not exists risk_history_device_idx on public.risk_history(device_id, recorded_at desc);
create index if not exists risk_history_time_idx on public.risk_history(recorded_at);

create table if not exists public.config_changes (
  id uuid primary key default gen_random_uuid(),
  device_id uuid not null references public.devices(id) on delete cascade,
  from_configuration_id uuid references public.configurations(id) on delete set null,
  to_configuration_id uuid references public.configurations(id) on delete cascade,
  added_lines integer not null default 0,
  removed_lines integer not null default 0,
  risky_changes jsonb not null default '[]'::jsonb,
  severity text,
  created_at timestamptz not null default now(),
  unique (to_configuration_id)
);
create index if not exists config_changes_device_idx on public.config_changes(device_id, created_at desc);

-- ─── Alerting ──────────────────────────────────────────────────────────────

create table if not exists public.alert_channels (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  kind text not null check (kind in ('slack', 'teams', 'webhook', 'email')),
  target text not null,
  min_severity text not null default 'HIGH' check (min_severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  events text[] not null default array['risk_increase', 'risky_change', 'kev_detected', 'device_unreachable', 'remediation_pending', 'remediation_result', 'weekly_digest'],
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.alert_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.organizations(id) on delete cascade,
  device_id uuid references public.devices(id) on delete cascade,
  kind text not null,
  severity text not null default 'MEDIUM',
  title text not null,
  body text,
  status text not null default 'pending' check (status in ('pending', 'sent', 'failed', 'suppressed')),
  delivered jsonb,
  created_at timestamptz not null default now(),
  sent_at timestamptz
);
create index if not exists alert_events_pending_idx on public.alert_events(status, created_at);

-- ─── Remediation workflow ──────────────────────────────────────────────────

create table if not exists public.remediation_requests (
  id uuid primary key default gen_random_uuid(),
  device_id uuid not null references public.devices(id) on delete cascade,
  rule_id text,
  title text not null,
  commands text not null,
  rollback_commands text not null default '',
  status text not null default 'pending_approval' check (status in (
    'pending_approval', 'approved', 'rejected', 'executing', 'applied',
    'verified', 'verification_failed', 'failed', 'rolling_back', 'rolled_back')),
  requested_by uuid references auth.users(id),
  requested_by_email text,
  approved_by uuid references auth.users(id),
  approved_by_email text,
  decided_at timestamptz,
  decision_note text,
  job_id uuid references public.agent_jobs(id) on delete set null,
  output text,
  pre_configuration_id uuid references public.configurations(id) on delete set null,
  post_configuration_id uuid references public.configurations(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- Four-eyes rule: nobody approves their own change.
  constraint remediation_two_person check (approved_by is null or approved_by <> requested_by)
);
create index if not exists remediation_device_idx on public.remediation_requests(device_id, created_at desc);

-- ─── Audit log ─────────────────────────────────────────────────────────────

create table if not exists public.audit_log (
  id bigserial primary key,
  org_id uuid references public.organizations(id) on delete set null,
  actor_id uuid,
  actor_email text,
  action text not null,
  target_type text,
  target_id text,
  details jsonb,
  ip text,
  created_at timestamptz not null default now()
);
create index if not exists audit_log_org_time_idx on public.audit_log(org_id, created_at desc);

-- ─── RLS helpers ───────────────────────────────────────────────────────────

create or replace function public.user_org_ids()
returns setof uuid
language sql stable security definer set search_path = public as $$
  select org_id from public.org_members where user_id = auth.uid()
$$;

create or replace function public.user_admin_org_ids()
returns setof uuid
language sql stable security definer set search_path = public as $$
  select org_id from public.org_members where user_id = auth.uid() and role = 'admin'
$$;

create or replace function public.can_see_device(p_device uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.devices d
     where d.id = p_device and d.org_id in (select public.user_org_ids()))
$$;

-- ─── Row Level Security ────────────────────────────────────────────────────

do $$
declare
  t text;
  pol record;
begin
  foreach t in array array['devices', 'configurations', 'scans', 'vulnerabilities'] loop
    for pol in select policyname from pg_policies where schemaname = 'public' and tablename = t loop
      execute format('drop policy if exists %I on public.%I', pol.policyname, t);
    end loop;
  end loop;
end $$;

alter table public.organizations enable row level security;
alter table public.org_members enable row level security;
alter table public.devices enable row level security;
alter table public.configurations enable row level security;
alter table public.scans enable row level security;
alter table public.vulnerabilities enable row level security;
alter table public.agent_jobs enable row level security;
alter table public.risk_history enable row level security;
alter table public.config_changes enable row level security;
alter table public.alert_channels enable row level security;
alter table public.alert_events enable row level security;
alter table public.remediation_requests enable row level security;
alter table public.audit_log enable row level security;

drop policy if exists aegis_org_read on public.organizations;
create policy aegis_org_read on public.organizations for select to authenticated
  using (id in (select public.user_org_ids()));

drop policy if exists aegis_members_read on public.org_members;
create policy aegis_members_read on public.org_members for select to authenticated
  using (org_id in (select public.user_org_ids()));

drop policy if exists aegis_devices_read on public.devices;
create policy aegis_devices_read on public.devices for select to authenticated
  using (org_id in (select public.user_org_ids()));

drop policy if exists aegis_configurations_read on public.configurations;
create policy aegis_configurations_read on public.configurations for select to authenticated
  using (public.can_see_device(device_id));

drop policy if exists aegis_scans_read on public.scans;
create policy aegis_scans_read on public.scans for select to authenticated
  using (public.can_see_device(device_id));

drop policy if exists aegis_vulns_read on public.vulnerabilities;
create policy aegis_vulns_read on public.vulnerabilities for select to authenticated
  using (exists (select 1 from public.scans s where s.id = scan_id and public.can_see_device(s.device_id)));

drop policy if exists aegis_jobs_read on public.agent_jobs;
create policy aegis_jobs_read on public.agent_jobs for select to authenticated
  using (public.can_see_device(device_id));

drop policy if exists aegis_risk_history_read on public.risk_history;
create policy aegis_risk_history_read on public.risk_history for select to authenticated
  using (public.can_see_device(device_id));

drop policy if exists aegis_config_changes_read on public.config_changes;
create policy aegis_config_changes_read on public.config_changes for select to authenticated
  using (public.can_see_device(device_id));

drop policy if exists aegis_remediation_read on public.remediation_requests;
create policy aegis_remediation_read on public.remediation_requests for select to authenticated
  using (public.can_see_device(device_id));

drop policy if exists aegis_alert_events_read on public.alert_events;
create policy aegis_alert_events_read on public.alert_events for select to authenticated
  using (org_id in (select public.user_org_ids()));

drop policy if exists aegis_alert_channels_read on public.alert_channels;
create policy aegis_alert_channels_read on public.alert_channels for select to authenticated
  using (org_id in (select public.user_admin_org_ids()));

drop policy if exists aegis_audit_read on public.audit_log;
create policy aegis_audit_read on public.audit_log for select to authenticated
  using (org_id in (select public.user_admin_org_ids()));

do $$ begin
  if to_regclass('public.suppliers') is not null then
    execute 'alter table public.suppliers enable row level security';
    execute 'drop policy if exists aegis_suppliers_read on public.suppliers';
    execute 'create policy aegis_suppliers_read on public.suppliers for select to authenticated using (true)';
  end if;
end $$;

-- ─── Hide credential columns from browser roles ────────────────────────────

do $$
declare
  cols text;
begin
  select string_agg(quote_ident(column_name), ', ')
    into cols
    from information_schema.columns
   where table_schema = 'public' and table_name = 'devices'
     and column_name not in ('ssh_pass', 'ssh_password', 'enable_pass', 'enable_password', 'password', 'secret');
  execute 'revoke select on public.devices from anon, authenticated';
  execute format('grant select (%s) on public.devices to authenticated', cols);
end $$;

-- ─── Vault credential RPC: service role only ───────────────────────────────

do $$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as sig from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.proname = 'get_device_credentials'
  loop
    execute format('revoke all on function %s from public, anon, authenticated', fn.sig);
    execute format('grant execute on function %s to service_role', fn.sig);
  end loop;
end $$;

-- ─── Realtime (replaces client polling) ────────────────────────────────────

do $$
declare
  t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['agent_jobs', 'scans', 'devices', 'remediation_requests'] loop
      begin
        execute format('alter publication supabase_realtime add table public.%I', t);
      exception when duplicate_object then null;
      end;
    end loop;
  end if;
end $$;
