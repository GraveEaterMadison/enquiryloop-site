-- EnquiryLoop tenant isolation hardening
-- Re-runnable migration. Run in Supabase SQL Editor after schema.sql.
-- Does not delete or rewrite customer rows.

begin;

-- SECURITY DEFINER avoids recursive RLS evaluation when policies inspect
-- workspace_members. All object references are schema-qualified.
create or replace function public.is_workspace_member(target_workspace uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.workspace_members as wm
    where wm.workspace_id = target_workspace
      and wm.user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_workspace_member(uuid) from public, anon;
grant execute on function public.is_workspace_member(uuid) to authenticated;

alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.profiles enable row level security;
alter table public.enquiries enable row level security;
alter table public.subscriptions enable row level security;

-- Remove every existing policy on these application tables so an older
-- permissive policy cannot OR-bypass the replacement policies below.
do $$
declare p record;
begin
  for p in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('workspaces','workspace_members','profiles','enquiries','subscriptions')
  loop
    execute format('drop policy if exists %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end
$$;

create policy "workspace members can read workspaces"
on public.workspaces for select to authenticated
using (public.is_workspace_member(id));

create policy "owners can update workspace"
on public.workspaces for update to authenticated
using (owner_id = (select auth.uid()))
with check (owner_id = (select auth.uid()));

create policy "members can read workspace memberships"
on public.workspace_members for select to authenticated
using (public.is_workspace_member(workspace_id));

create policy "users can read own profile"
on public.profiles for select to authenticated
using (id = (select auth.uid()));

create policy "users can update own profile"
on public.profiles for update to authenticated
using (id = (select auth.uid()))
with check (id = (select auth.uid()));

create policy "members can read workspace enquiries"
on public.enquiries for select to authenticated
using (public.is_workspace_member(workspace_id));

create policy "members can create workspace enquiries"
on public.enquiries for insert to authenticated
with check (
  public.is_workspace_member(workspace_id)
  and created_by = (select auth.uid())
);

create policy "members can update workspace enquiries"
on public.enquiries for update to authenticated
using (public.is_workspace_member(workspace_id))
with check (public.is_workspace_member(workspace_id));

create policy "members can delete workspace enquiries"
on public.enquiries for delete to authenticated
using (public.is_workspace_member(workspace_id));

create policy "members can read workspace subscription"
on public.subscriptions for select to authenticated
using (public.is_workspace_member(workspace_id));

-- Remove table-level browser privileges, including TRUNCATE/REFERENCES/TRIGGER.
revoke all privileges on table
  public.workspaces,
  public.workspace_members,
  public.profiles,
  public.enquiries,
  public.subscriptions
from public, anon, authenticated;

grant usage on schema public to authenticated;
grant select on public.workspaces to authenticated;
grant update (name) on public.workspaces to authenticated;
grant select on public.workspace_members to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.enquiries to authenticated;
grant select on public.subscriptions to authenticated;

commit;
