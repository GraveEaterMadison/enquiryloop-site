create extension if not exists pgcrypto;
create table if not exists public.workspaces(id uuid primary key default gen_random_uuid(),name text not null check(char_length(name) between 2 and 100),owner_id uuid not null references auth.users(id) on delete cascade,plan text not null default 'free' check(plan in('free','starter','pro')),created_at timestamptz not null default now());
create table if not exists public.workspace_members(workspace_id uuid not null references public.workspaces(id) on delete cascade,user_id uuid not null references auth.users(id) on delete cascade,role text not null default 'owner' check(role in('owner','admin','staff')),created_at timestamptz not null default now(),primary key(workspace_id,user_id));
create table if not exists public.profiles(id uuid primary key references auth.users(id) on delete cascade,full_name text,created_at timestamptz not null default now());
create table if not exists public.enquiries(id uuid primary key default gen_random_uuid(),workspace_id uuid not null references public.workspaces(id) on delete cascade,student_name text not null check(char_length(student_name) between 1 and 120),phone text,email text,course text,status text not null default 'New' check(status in('New','Contacted','Follow-up','Admitted','Not interested')),source text,follow_up_at date,notes text,created_by uuid references auth.users(id) on delete set null,created_at timestamptz not null default now(),updated_at timestamptz not null default now());
create index if not exists enquiries_workspace_created_idx on public.enquiries(workspace_id,created_at desc);
create index if not exists enquiries_workspace_followup_idx on public.enquiries(workspace_id,follow_up_at);
create index if not exists workspace_members_user_idx on public.workspace_members(user_id);
create table if not exists public.subscriptions(workspace_id uuid primary key references public.workspaces(id) on delete cascade,provider text,provider_customer_id text,provider_subscription_id text,status text not null default 'free' check(status in('free','trialing','active','past_due','cancelled')),current_period_end timestamptz,updated_at timestamptz not null default now());
create or replace function public.is_workspace_member(target_workspace uuid) returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from public.workspace_members wm where wm.workspace_id=target_workspace and wm.user_id=auth.uid()); $$;
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare wid uuid; bname text;
begin
 insert into public.profiles(id,full_name) values(new.id,coalesce(new.raw_user_meta_data->>'full_name','')) on conflict(id) do nothing;
 bname:=coalesce(nullif(trim(new.raw_user_meta_data->>'business_name'),''),'My education business');
 insert into public.workspaces(name,owner_id) values(bname,new.id) returning id into wid;
 insert into public.workspace_members(workspace_id,user_id,role) values(wid,new.id,'owner');
 insert into public.subscriptions(workspace_id,status) values(wid,'free');
 return new;
end; $$;
drop trigger if exists on_auth_user_created_enquiryloop on auth.users;
create trigger on_auth_user_created_enquiryloop after insert on auth.users for each row execute procedure public.handle_new_user();
create or replace function public.enforce_free_plan_limit() returns trigger language plpgsql security definer set search_path=public as $$
declare p text; n integer;
begin
 select plan into p from public.workspaces where id=new.workspace_id for update;
 if p='free' then
  select count(*) into n from public.enquiries where workspace_id=new.workspace_id;
  if n>=50 then raise exception 'Free plan limit reached (50 enquiries). Upgrade your plan to add more.'; end if;
 end if;
 new.updated_at:=now(); return new;
end; $$;
drop trigger if exists enforce_enquiryloop_free_limit on public.enquiries;
create trigger enforce_enquiryloop_free_limit before insert on public.enquiries for each row execute procedure public.enforce_free_plan_limit();
create or replace function public.touch_enquiry_updated_at() returns trigger language plpgsql as $$ begin new.updated_at:=now(); return new; end; $$;
drop trigger if exists touch_enquiry_updated_at on public.enquiries;
create trigger touch_enquiry_updated_at before update on public.enquiries for each row execute procedure public.touch_enquiry_updated_at();
alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.profiles enable row level security;
alter table public.enquiries enable row level security;
alter table public.subscriptions enable row level security;
drop policy if exists "members can view own workspaces" on public.workspaces;
create policy "members can view own workspaces" on public.workspaces for select using(public.is_workspace_member(id));
drop policy if exists "owners can update workspace" on public.workspaces;
create policy "owners can update workspace" on public.workspaces for update using(owner_id=auth.uid()) with check(owner_id=auth.uid());
drop policy if exists "members can view workspace membership" on public.workspace_members;
create policy "members can view workspace membership" on public.workspace_members for select using(public.is_workspace_member(workspace_id));
drop policy if exists "users can view own profile" on public.profiles;
create policy "users can view own profile" on public.profiles for select using(id=auth.uid());
drop policy if exists "users can update own profile" on public.profiles;
create policy "users can update own profile" on public.profiles for update using(id=auth.uid()) with check(id=auth.uid());
drop policy if exists "members can read enquiries" on public.enquiries;
create policy "members can read enquiries" on public.enquiries for select using(public.is_workspace_member(workspace_id));
drop policy if exists "members can add enquiries" on public.enquiries;
create policy "members can add enquiries" on public.enquiries for insert with check(public.is_workspace_member(workspace_id) and created_by=auth.uid());
drop policy if exists "members can update enquiries" on public.enquiries;
create policy "members can update enquiries" on public.enquiries for update using(public.is_workspace_member(workspace_id)) with check(public.is_workspace_member(workspace_id));
drop policy if exists "members can delete enquiries" on public.enquiries;
create policy "members can delete enquiries" on public.enquiries for delete using(public.is_workspace_member(workspace_id));
drop policy if exists "members can view subscription status" on public.subscriptions;
create policy "members can view subscription status" on public.subscriptions for select using(public.is_workspace_member(workspace_id));
-- No browser-side write policy exists for subscriptions. Only a trusted server-side webhook may change billing state.
