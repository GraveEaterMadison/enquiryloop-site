-- EnquiryLoop workspace settings and least-privilege browser permissions.
-- Run after schema.sql / tenant isolation hardening.

revoke all privileges on table public.workspaces, public.workspace_members, public.profiles,
  public.enquiries, public.subscriptions from public, anon, authenticated;

grant usage on schema public to authenticated;
grant select on public.workspaces to authenticated;
grant update (name) on public.workspaces to authenticated;
grant select on public.workspace_members to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.enquiries to authenticated;
grant select on public.subscriptions to authenticated;

-- The RLS helper is intentionally in the non-exposed private schema.
revoke all on function private.is_workspace_member(uuid) from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.is_workspace_member(uuid) to authenticated;

-- Trigger functions are not browser-callable RPC endpoints.
revoke all on function public.handle_new_user() from public, anon, authenticated;
revoke all on function public.enforce_free_plan_limit() from public, anon, authenticated;
revoke all on function public.touch_enquiry_updated_at() from public, anon, authenticated;
