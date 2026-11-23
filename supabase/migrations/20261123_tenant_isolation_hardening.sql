-- EnquiryLoop tenant isolation hardening.
-- Applies explicit authenticated-only policies and a private RLS helper.
begin;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

create or replace function private.is_workspace_member(target_workspace uuid)
returns boolean language sql stable security definer set search_path = ''
as $function$
  select exists (
    select 1 from public.workspace_members wm
    where wm.workspace_id=target_workspace and wm.user_id=(select auth.uid())
  );
$function$;
revoke all on function private.is_workspace_member(uuid) from public, anon, authenticated;
grant execute on function private.is_workspace_member(uuid) to authenticated;

alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.profiles enable row level security;
alter table public.enquiries enable row level security;
alter table public.subscriptions enable row level security;

alter policy "members can view own workspaces" on public.workspaces to authenticated
using (private.is_workspace_member(id));
alter policy "owners can update workspace" on public.workspaces to authenticated
using (owner_id=(select auth.uid())) with check (owner_id=(select auth.uid()));
alter policy "members can view workspace membership" on public.workspace_members to authenticated
using (private.is_workspace_member(workspace_id));
alter policy "users can view own profile" on public.profiles to authenticated
using (id=(select auth.uid()));
alter policy "users can update own profile" on public.profiles to authenticated
using (id=(select auth.uid())) with check (id=(select auth.uid()));
alter policy "members can read enquiries" on public.enquiries to authenticated
using (private.is_workspace_member(workspace_id));
alter policy "members can add enquiries" on public.enquiries to authenticated
with check (private.is_workspace_member(workspace_id) and created_by=(select auth.uid()));
alter policy "members can update enquiries" on public.enquiries to authenticated
using (private.is_workspace_member(workspace_id)) with check (private.is_workspace_member(workspace_id));
alter policy "members can delete enquiries" on public.enquiries to authenticated
using (private.is_workspace_member(workspace_id));
alter policy "members can view subscription status" on public.subscriptions to authenticated
using (private.is_workspace_member(workspace_id));

drop function if exists public.is_workspace_member(uuid);

revoke all privileges on table public.workspaces, public.workspace_members, public.profiles,
  public.enquiries, public.subscriptions from public, anon, authenticated;
grant usage on schema public to authenticated;
grant select on public.workspaces to authenticated;
grant update (name) on public.workspaces to authenticated;
grant select on public.workspace_members to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.enquiries to authenticated;
grant select on public.subscriptions to authenticated;

revoke all on function public.handle_new_user() from public, anon, authenticated;
revoke all on function public.enforce_free_plan_limit() from public, anon, authenticated;
revoke all on function public.touch_enquiry_updated_at() from public, anon, authenticated;
commit;
