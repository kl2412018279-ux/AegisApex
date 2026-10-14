-- Minimal stand-in for the parts of a Supabase project the migration touches,
-- so the migration can be tested against plain Postgres. Not for production.
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;
create schema auth;
create table auth.users (id uuid primary key, email text);
create function auth.uid() returns uuid language sql stable as
  $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
grant usage on schema auth to anon, authenticated, service_role;
grant execute on function auth.uid() to anon, authenticated;
create publication supabase_realtime;

create table public.suppliers (id uuid primary key default gen_random_uuid(), name text);
create table public.devices (
  id uuid primary key default gen_random_uuid(),
  hostname text, ip_address text, management_ip text, vendor text, netmiko_type text,
  connection_status text default 'online', risk_level text, ssh_user text, ssh_pass text,
  last_config text, raw_version text, os_version text, last_seen_at timestamptz,
  supplier_id uuid references public.suppliers(id), created_at timestamptz default now());
create table public.configurations (
  id uuid primary key default gen_random_uuid(), device_id uuid references public.devices(id),
  raw_config text, content text, created_at timestamptz default now(), updated_at timestamptz);
create table public.scans (
  id uuid primary key default gen_random_uuid(), device_id uuid references public.devices(id),
  configuration_id uuid not null references public.configurations(id), raw_version text, summary text,
  os_summary text, risk_level text, status text, model_used text, target_firmware text, eol_status text,
  created_at timestamptz default now(), updated_at timestamptz);
create table public.vulnerabilities (
  id uuid primary key default gen_random_uuid(), scan_id uuid references public.scans(id), title text,
  severity text check (severity in ('Critical','High','Medium','Low','Informational','Safe')),
  description text, affected_config_line text, remediation_cli text);
create function public.get_device_credentials(p_device_id uuid)
  returns table(ssh_user text, ssh_pass text, enable_pass text) language sql as $$ select null::text, null::text, null::text $$;
grant usage on schema public to anon, authenticated, service_role;
grant all on all tables in schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
grant execute on function public.get_device_credentials(uuid) to anon, authenticated;

-- A pre-existing permissive policy the migration must remove.
alter table public.devices enable row level security;
create policy "allow all" on public.devices for all using (true);
