-- NEXUS community improvements: bookmarks, edit history, reposts, reports,
-- blocks, account settings, archive metadata, post pins, and reward limits.
-- Safe to rerun. Execute in the Supabase SQL Editor.

alter table public.posts
  add column if not exists edited_at timestamptz,
  add column if not exists quote_post_id text;

alter table public.profiles
  add column if not exists bio text,
  add column if not exists notification_settings jsonb not null default '{"likes":true,"comments":true,"follows":true,"messages":true}'::jsonb,
  add column if not exists pinned_post_id text;

alter table public.archive_documents
  add column if not exists description text not null default '',
  add column if not exists tags text[] not null default '{}';
grant update on public.archive_documents to authenticated;
drop policy if exists "Members can update their own archive documents" on public.archive_documents;
create policy "Members can update their own archive documents" on public.archive_documents
  for update to authenticated using (user_id=(select auth.uid())) with check (user_id=(select auth.uid()));

create table if not exists public.archive_document_versions (
  id uuid primary key default gen_random_uuid(),
  document_id uuid not null references public.archive_documents(id) on delete cascade,
  uploaded_by uuid not null references public.profiles(id) on delete cascade,
  storage_path text not null unique,
  original_name text not null,
  created_at timestamptz not null default now()
);
alter table public.archive_document_versions enable row level security;
revoke all on public.archive_document_versions from anon;
grant select, insert on public.archive_document_versions to authenticated;
drop policy if exists "Authenticated users can view PDF history" on public.archive_document_versions;
create policy "Authenticated users can view PDF history" on public.archive_document_versions for select to authenticated using (true);
drop policy if exists "Owners can save prior PDF versions" on public.archive_document_versions;
create policy "Owners can save prior PDF versions" on public.archive_document_versions for insert to authenticated
  with check (uploaded_by=(select auth.uid()) and exists(select 1 from public.archive_documents d where d.id=document_id and d.user_id=(select auth.uid())));

create table if not exists public.nexus_badges (
  user_id uuid not null references public.profiles(id) on delete cascade,
  badge text not null,
  label text not null,
  created_at timestamptz not null default now(),
  primary key(user_id,badge)
);
alter table public.nexus_badges enable row level security;
revoke all on public.nexus_badges from anon, authenticated;
grant select on public.nexus_badges to authenticated;
drop policy if exists "Authenticated users can view profile badges" on public.nexus_badges;
create policy "Authenticated users can view profile badges" on public.nexus_badges for select to authenticated using (true);

create table if not exists public.post_bookmarks (
  user_id uuid not null references public.profiles(id) on delete cascade,
  post_id text not null,
  created_at timestamptz not null default now(),
  primary key (user_id, post_id)
);
alter table public.post_bookmarks enable row level security;
revoke all on public.post_bookmarks from anon;
grant select, insert, delete on public.post_bookmarks to authenticated;
drop policy if exists "Users manage their own bookmarks" on public.post_bookmarks;
create policy "Users manage their own bookmarks" on public.post_bookmarks
  for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

create table if not exists public.post_edit_history (
  id uuid primary key default gen_random_uuid(),
  post_id text not null,
  user_id uuid not null references public.profiles(id) on delete cascade,
  previous_content text not null,
  edited_at timestamptz not null default now()
);
alter table public.post_edit_history enable row level security;
revoke all on public.post_edit_history from anon;
grant select, insert on public.post_edit_history to authenticated;
drop policy if exists "Post authors and readers can view edit history" on public.post_edit_history;
create policy "Post authors and readers can view edit history" on public.post_edit_history
  for select to authenticated using (true);
drop policy if exists "Authors can record their edits" on public.post_edit_history;
create policy "Authors can record their edits" on public.post_edit_history
  for insert to authenticated with check (user_id = (select auth.uid()));

create table if not exists public.user_blocks (
  blocker_id uuid not null references public.profiles(id) on delete cascade,
  blocked_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);
alter table public.user_blocks enable row level security;
revoke all on public.user_blocks from anon;
grant select, insert, update, delete on public.user_blocks to authenticated;
drop policy if exists "Users manage their own blocks" on public.user_blocks;
create policy "Users manage their own blocks" on public.user_blocks
  for all to authenticated using (blocker_id = (select auth.uid())) with check (blocker_id = (select auth.uid()));

create table if not exists public.content_reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references public.profiles(id) on delete cascade,
  target_type text not null check (target_type in ('post','comment','profile','archive_document')),
  target_id text not null,
  reason text not null check (reason in ('spam','harassment','unsafe','copyright','other')),
  details text not null default '',
  status text not null default 'pending' check (status in ('pending','reviewed','actioned','dismissed')),
  reviewed_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists content_reports_status_created_idx on public.content_reports(status, created_at desc);
alter table public.content_reports enable row level security;
revoke all on public.content_reports from anon;
grant select, insert, update on public.content_reports to authenticated;
drop policy if exists "Users submit and view their own reports" on public.content_reports;
create policy "Users submit and view their own reports" on public.content_reports
  for select to authenticated using (reporter_id = (select auth.uid()));
drop policy if exists "Users can submit reports" on public.content_reports;
create policy "Users can submit reports" on public.content_reports
  for insert to authenticated with check (reporter_id = (select auth.uid()));
-- Moderators are assigned by a trusted project administrator, never by profile editing.
-- Assign a moderator with: INSERT INTO public.nexus_moderators(user_id) VALUES ('AUTH-USER-UUID');
create table if not exists public.nexus_moderators (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.nexus_moderators enable row level security;
revoke all on public.nexus_moderators from anon, authenticated;
create or replace function public.is_current_user_moderator()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.nexus_moderators where user_id = (select auth.uid()));
$$;
revoke all on function public.is_current_user_moderator() from public;
grant execute on function public.is_current_user_moderator() to authenticated;
drop policy if exists "Moderators can review reports" on public.content_reports;
create policy "Moderators can review reports" on public.content_reports
  for all to authenticated
  using (public.is_current_user_moderator())
  with check (public.is_current_user_moderator());

-- Allow a signed-in member to permanently delete only their own account.
create or replace function public.delete_my_account()
returns void language plpgsql security definer set search_path = '' as $$
declare target_user uuid := auth.uid();
begin
  if target_user is null then raise exception 'Sign in before deleting an account'; end if;
  delete from storage.objects
    where bucket_id in ('post-media','avatars','hidden-archive')
      and (storage.foldername(name))[1] = target_user::text;
  delete from public.credit_rewards where user_id = target_user;
  delete from auth.users where id = target_user;
  if not found then raise exception 'Account was not found'; end if;
end;
$$;
revoke all on function public.delete_my_account() from public;
grant execute on function public.delete_my_account() to authenticated;

-- Validate a user's pinned post belongs to them.
create or replace function public.validate_profile_pin()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.pinned_post_id is not null and not exists (
    select 1 from public.posts p where p.id::text = new.pinned_post_id and p.user_id = new.id
  ) then raise exception 'Pinned post must belong to this profile'; end if;
  return new;
end;
$$;
drop trigger if exists profiles_validate_pin_insert on public.profiles;
drop trigger if exists profiles_validate_pin_update on public.profiles;
create trigger profiles_validate_pin_insert before insert on public.profiles
  for each row execute function public.validate_profile_pin();
create trigger profiles_validate_pin_update before update of pinned_post_id on public.profiles
  for each row execute function public.validate_profile_pin();

-- Cap reward farming at $2.00/day and limit bursts while allowing normal use.
create or replace function public.reward_new_post()
returns trigger language plpgsql security definer set search_path = '' as $$
declare reward_amount numeric; recorded_source text;
begin
  if (select count(*) from public.posts p where p.user_id = new.user_id and p.created_at > now() - interval '1 hour') > 20 then
    raise exception 'Posting limit reached. Try again later.';
  end if;
  reward_amount := greatest(0, 2.00 - coalesce((select sum(r.amount) from public.credit_rewards r where r.user_id = new.user_id and r.created_at >= date_trunc('day', now())), 0));
  reward_amount := least(0.50, reward_amount);
  insert into public.credit_rewards (source_type, source_id, user_id, amount)
  values ('post', new.id::text, new.user_id, reward_amount)
  on conflict (source_type, source_id) do nothing returning source_id into recorded_source;
  if recorded_source is not null and reward_amount > 0 then
    update public.profiles set credits = coalesce(credits, 0) + reward_amount where id = new.user_id;
  end if;
  return new;
end;
$$;

create or replace function public.reward_new_comment()
returns trigger language plpgsql security definer set search_path = '' as $$
declare reward_amount numeric; recorded_source text;
begin
  if (select count(*) from public.comments c where c.user_id = new.user_id and c.created_at > now() - interval '1 hour') > 60 then
    raise exception 'Comment limit reached. Try again later.';
  end if;
  reward_amount := case when new.parent_comment_id is null or btrim(new.parent_comment_id) = '' then 0.10 else 0.05 end;
  reward_amount := least(reward_amount, greatest(0, 2.00 - coalesce((select sum(r.amount) from public.credit_rewards r where r.user_id = new.user_id and r.created_at >= date_trunc('day', now())), 0)));
  insert into public.credit_rewards (source_type, source_id, user_id, amount)
  values ('comment', new.id::text, new.user_id, reward_amount)
  on conflict (source_type, source_id) do nothing returning source_id into recorded_source;
  if recorded_source is not null and reward_amount > 0 then
    update public.profiles set credits = coalesce(credits, 0) + reward_amount where id = new.user_id;
  end if;
  return new;
end;
$$;

notify pgrst, 'reload schema';
