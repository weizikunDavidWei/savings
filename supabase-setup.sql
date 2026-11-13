-- SAVINGS. optional cloud sync / schema v1
-- Run in your own Supabase project's SQL Editor. No cloud setup is needed for local use.
-- Each entity has its own revision. Tombstones are retained to sync deletions.

create table if not exists public.savings_records (
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  entity_type text not null check (entity_type in ('transactions','quick','goals','categories','preferences')),
  entity_id text not null check (length(entity_id) between 1 and 200),
  payload jsonb not null,
  -- Canonical UTC ISO text is used so browser and database compare identical revisions.
  updated_at text not null check (updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'),
  rev text not null check (length(rev) between 1 and 200),
  primary key (user_id, entity_type, entity_id),
  constraint payload_id_matches check (payload->>'id' = entity_id),
  constraint payload_time_matches check (payload->>'updatedAt' = updated_at),
  constraint payload_revision_matches check (payload->>'rev' = rev),
  constraint payload_has_tombstone check (jsonb_typeof(payload->'deleted') = 'boolean'),
  constraint payload_size_limit check (octet_length(payload::text) < 2000000)
);

alter table public.savings_records enable row level security;
-- Explicit grants: no anonymous database access, and no physical deletion by browsers.
revoke all on public.savings_records from anon;
revoke all on public.savings_records from authenticated;
grant select, insert, update on public.savings_records to authenticated;

drop policy if exists "Read own savings" on public.savings_records;
create policy "Read own savings" on public.savings_records for select to authenticated
  using ((select auth.uid()) = user_id);
drop policy if exists "Insert own savings" on public.savings_records;
create policy "Insert own savings" on public.savings_records for insert to authenticated
  with check ((select auth.uid()) = user_id);
drop policy if exists "Update own savings" on public.savings_records;
create policy "Update own savings" on public.savings_records for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

-- SECURITY INVOKER keeps the caller's RLS isolation in force.
-- The condition is checked atomically by Postgres: stale devices cannot overwrite
-- newer server revisions even when two devices push simultaneously.
create or replace function public.merge_savings_records(records jsonb)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  if jsonb_typeof(records) <> 'array' or jsonb_array_length(records) > 100 then
    raise exception 'Expected an array of at most 100 records';
  end if;

  insert into public.savings_records as existing
    (user_id, entity_type, entity_id, payload, updated_at, rev)
  select auth.uid(), r.entity_type, r.entity_id, r.payload, r.updated_at, r.rev
  from jsonb_to_recordset(records) as r(
    entity_type text, entity_id text, payload jsonb, updated_at text, rev text
  )
  on conflict (user_id, entity_type, entity_id)
  do update set payload = excluded.payload,
                updated_at = excluded.updated_at,
                rev = excluded.rev
  where (excluded.updated_at collate "C", excluded.rev collate "C")
      > (existing.updated_at collate "C", existing.rev collate "C");
end;
$$;

revoke all on function public.merge_savings_records(jsonb) from public, anon;
grant execute on function public.merge_savings_records(jsonb) to authenticated;
