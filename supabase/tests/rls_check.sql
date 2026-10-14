-- Run after the migration on the shim. Fails (ON_ERROR_STOP) on any violation.
\set ON_ERROR_STOP on
insert into auth.users values ('11111111-1111-1111-1111-111111111111', 'admin@example.com');
insert into auth.users values ('22222222-2222-2222-2222-222222222222', 'outsider@example.com');
insert into public.organizations (id, name) values ('00000000-0000-0000-0000-000000000002', 'Other Org');
insert into public.org_members values ('00000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'admin');
insert into public.org_members values ('00000000-0000-0000-0000-000000000002', '22222222-2222-2222-2222-222222222222', 'viewer');
insert into public.devices (id, hostname, ssh_pass, org_id) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'R1', 'hunter2', '00000000-0000-0000-0000-000000000001');
insert into public.agent_jobs (device_id, kind) values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'collect');

do $$
declare n int; ok boolean;
begin
  -- admin of the default org sees the device
  perform set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
  set local role authenticated;
  select count(*) into n from public.devices;
  if n <> 1 then raise exception 'admin should see 1 device, saw %', n; end if;
  select count(*) into n from public.agent_jobs;
  if n <> 1 then raise exception 'admin should see 1 job, saw %', n; end if;
  -- the dashboard's explicit column list (dashboard/_hooks/dashboardData.ts) is readable
  perform id, hostname, ip_address, management_ip, vendor, netmiko_type, connection_status, last_seen_at,
          created_at, risk_level, last_config, raw_version, os_version, org_id, is_mock,
          collection_interval_minutes, next_collection_at, last_collection_error,
          ssh_host_key_fingerprint, ssh_host_key_pinned_at
     from public.devices;
  -- credential column is not readable
  begin
    perform ssh_pass from public.devices;
    raise exception 'ssh_pass was readable by authenticated';
  exception when insufficient_privilege then null;
  end;
  -- browser role cannot write
  begin
    update public.devices set hostname = 'pwned';
    get diagnostics n = row_count;
    if n > 0 then raise exception 'authenticated could update devices'; end if;
  exception when insufficient_privilege then null;
  end;
  -- vault RPC is not callable
  begin
    perform public.get_device_credentials('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    raise exception 'authenticated could call get_device_credentials';
  exception when insufficient_privilege then null;
  end;
  reset role;

  -- member of another org sees nothing
  perform set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true);
  set local role authenticated;
  select count(*) into n from public.devices;
  if n <> 0 then raise exception 'outsider saw % devices', n; end if;
  select count(*) into n from public.audit_log;
  reset role;

  -- anonymous sees nothing
  set local role anon;
  begin
    select count(*) into n from public.devices;
    raise exception 'anon could read devices';
  exception when insufficient_privilege then null;
  end;
  reset role;
end $$;

-- queue functions: a due device is queued exactly once; mock devices never
insert into public.devices (hostname, org_id) values ('R2', '00000000-0000-0000-0000-000000000001');
insert into public.devices (hostname, org_id, is_mock) values ('LAB', '00000000-0000-0000-0000-000000000001', true);
do $$
declare n int;
begin
  n := public.enqueue_due_collections();
  if n <> 1 then raise exception 'expected 1 queued collection, got %', n; end if;
  n := public.enqueue_due_collections();
  if n <> 0 then raise exception 'second run should queue nothing, got %', n; end if;
  select count(*) into n from public.claim_agent_job('w1');
  if n <> 1 then raise exception 'claim returned % rows', n; end if;
  select count(*) into n from public.agent_jobs where status = 'running';
  if n <> 1 then raise exception 'expected 1 running job, got %', n; end if;
end $$;

-- four-eyes constraint
do $$ begin
  insert into public.remediation_requests (device_id, title, commands, requested_by, approved_by)
  values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 't', 'x', '11111111-1111-1111-1111-111111111111', '11111111-1111-1111-1111-111111111111');
  raise exception 'self-approval was allowed';
exception when check_violation then null;
end $$;
-- global rate limit: 3 allowed, 4th refused with a retry hint, other keys unaffected
do $$
declare r record; i int;
begin
  for i in 1..3 loop
    select * into r from public.check_rate_limit('ai-scan:u1', 3, 60);
    if not r.allowed then raise exception 'hit % should be allowed', i; end if;
  end loop;
  select * into r from public.check_rate_limit('ai-scan:u1', 3, 60);
  if r.allowed or r.retry_after < 1 then raise exception 'fourth hit should be refused with retry_after'; end if;
  select * into r from public.check_rate_limit('ai-scan:u2', 3, 60);
  if not r.allowed then raise exception 'other key should be allowed'; end if;
  set local role authenticated;
  begin
    perform public.check_rate_limit('x', 1, 1);
    raise exception 'authenticated could call check_rate_limit';
  exception when insufficient_privilege then null;
  end;
  reset role;
end $$;
select 'RLS CHECKS PASSED';
