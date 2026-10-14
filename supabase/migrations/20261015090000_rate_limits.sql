-- AegisApex follow-up migration: global rate limiting.
-- Apply after 20261014120000_aegisapex_upgrades.sql. Safe to re-run.
--
-- Rate limits used to live in each server instance's memory, so N instances
-- meant N × the limit. This keeps one sliding window per key in Postgres.

create table if not exists public.rate_limit_hits (
  key text not null,
  hit_at timestamptz not null default now()
);
create index if not exists rate_limit_hits_key_time_idx on public.rate_limit_hits(key, hit_at);
alter table public.rate_limit_hits enable row level security;  -- no policies: service role only

create or replace function public.check_rate_limit(p_key text, p_limit integer, p_window_seconds integer)
returns table(allowed boolean, retry_after integer)
language plpgsql security definer set search_path = public as $$
declare
  n integer;
  oldest timestamptz;
begin
  -- Serialize callers for the same key so two requests can't both take the last slot.
  perform pg_advisory_xact_lock(hashtext(p_key));
  delete from public.rate_limit_hits
   where key = p_key and hit_at < now() - make_interval(secs => p_window_seconds);
  select count(*), min(hit_at) into n, oldest from public.rate_limit_hits where key = p_key;
  if n >= p_limit then
    return query select false,
      greatest(1, ceil(extract(epoch from (oldest + make_interval(secs => p_window_seconds) - now()))))::integer;
    return;
  end if;
  insert into public.rate_limit_hits (key) values (p_key);
  return query select true, 0;
end $$;

revoke all on function public.check_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.check_rate_limit(text, integer, integer) to service_role;

-- Old rows for keys that are never hit again: trimmed by /api/cron/process.
create or replace function public.prune_rate_limit_hits()
returns integer
language sql security definer set search_path = public as $$
  with gone as (delete from public.rate_limit_hits where hit_at < now() - interval '1 day' returning 1)
  select count(*)::integer from gone
$$;
revoke all on function public.prune_rate_limit_hits() from public, anon, authenticated;
grant execute on function public.prune_rate_limit_hits() to service_role;
