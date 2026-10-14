-- Devices added after the first migration (e.g. from the Supabase table
-- editor) had no org_id, so RLS hid them from everyone and the inventory
-- looked empty. New devices now default to the Default Organization, and
-- any that slipped through are moved there. Safe to re-run.

alter table public.devices
  alter column org_id set default '00000000-0000-0000-0000-000000000001';

update public.devices
   set org_id = '00000000-0000-0000-0000-000000000001'
 where org_id is null;
