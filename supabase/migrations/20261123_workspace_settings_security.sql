-- EnquiryLoop workspace settings and least-privilege permissions
-- Safe to run after the original schema and prior dashboard permission fixes.

GRANT USAGE ON SCHEMA public TO authenticated;

-- Members can read workspaces subject to RLS, but only owners can update the name.
GRANT SELECT ON public.workspaces TO authenticated;
REVOKE UPDATE ON public.workspaces FROM authenticated;
GRANT UPDATE (name) ON public.workspaces TO authenticated;

-- Keep the browser grants required by the current app.
GRANT SELECT ON public.workspace_members TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.enquiries TO authenticated;
GRANT SELECT, UPDATE ON public.profiles TO authenticated;
GRANT SELECT ON public.subscriptions TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_workspace_member(uuid) TO authenticated;

-- Do not grant browser-side INSERT/UPDATE/DELETE on subscriptions.
