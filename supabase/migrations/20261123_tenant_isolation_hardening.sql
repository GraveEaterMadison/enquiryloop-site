-- EnquiryLoop: restore tenant isolation and least-privilege browser access.
-- Apply after the original schema. Safe to run more than once.
begin;

-- Membership lookup is SECURITY DEFINER to avoid recursive RLS evaluation
-- when workspace_members policies call this helper.
create or replace function public.is_workspace_member(target_workspace uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.workspace_members wm
    where wm.workspace_id = target_workspace
      and wm.user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_workspace_member(uuid) from public;
grant execute on function public.is_workspace_member(uuid) to authenticated;

-- Ensure RLS is enabled on every tenant-bearing table.
alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.profiles enable row level security;
alter table public.enquiries enable row level security;
alter table public.subscriptions enable row level security;

-- Replace potentially permissive/obsolete policies with explicit authenticated policies.
drop policy if exists "members can view own workspaces" on public.workspaces;
drop policy if exists "owners can update workspace" on public.workspaces;
drop policy if exists "members can view workspace membership" on public.workspace_members;
drop policy if exists "users can view own profile" on public.profiles;
drop policy if exists "users can update own profile" on public.profiles;
drop policy if exists "members can read enquiries" on public.enquiries;
drop policy if exists "members can add enquiries" on public.enquiries;
drop policy if exists "members can update enquiries" on public.enquiries;
drop policy if exists "members can delete enquiries" on public.enquiries;
drop policy if exists "members can view subscription status" on public.subscriptions;

create policy "authenticated members read own workspaces"
on public.workspaces for select to authenticated
using (public.is_workspace_member(id));

create policy "workspace owners update workspace name"
on public.workspaces for update to authenticated
using (owner_id = (select auth.uid()))
with check (owner_id = (select auth.uid()));

create policy "authenticated members read own memberships"
on public.workspace_members for select to authenticated
using (public.is_workspace_member(workspace_id));

create policy "users read own profile"
on public.profiles for select to authenticated
using (id = (select auth.uid()));

create policy "users update own profile"
on public.profiles for update to authenticated
using (id = (select auth.uid()))
with check (id = (select auth.uid()));

create policy "workspace members read enquiries"
on public.enquiries for select to authenticated
using (public.is_workspace_member(workspace_id));

create policy "workspace members insert own enquiries"
on public.enquiries for insert to authenticated
with check (
  public.is_workspace_member(workspace_id)
  and created_by = (select auth.uid())
);

create policy "workspace members update own enquiries"
on public.enquiries for update to authenticated
using (public.is_workspace_member(workspace_id))
with check (public.is_workspace_member(workspace_id));

create policy "workspace members delete own enquiries"
on public.enquiries for delete to authenticated
using (public.is_workspace_member(workspace_id));

create policy "workspace members read subscription status"
on public.subscriptions for select to authenticated
using (public.is_workspace_member(workspace_id));

-- Reset browser privileges first, removing broad grants such as TRUNCATE.
revoke all privileges on table
  public.workspaces,
  public.workspace_members,
  public.profiles,
  public.enquiries,
  public.subscriptions
from anon, authenticated;

grant usage on schema public to authenticated;

grant select on public.workspaces to authenticated;
grant update (name) on public.workspaces to authenticated;
grant select on public.workspace_members to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.enquiries to authenticated;
grant select on public.subscriptions to authenticated;

commit;
