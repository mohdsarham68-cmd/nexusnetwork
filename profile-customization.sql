-- Adds persistent profile cover images for the NEXUS profile editor.
alter table public.profiles
  add column if not exists cover_url text,
  add column if not exists bio text;

-- Avatar uploads must persist on the profile so they survive a reload.
alter table public.profiles
  add column if not exists avatar_url text;

-- The profile editor and account triggers also read this balance field.
alter table public.profiles
  add column if not exists credits numeric not null default 0;

-- Public UIDs are editable aliases; the Supabase Auth UUID stays unchanged.
alter table public.profiles
  add column if not exists public_uid text,
  add column if not exists public_uid_change_used boolean not null default false;

update public.profiles
set public_uid = id::text
where public_uid is null or btrim(public_uid) = '';

alter table public.profiles
  alter column public_uid set default gen_random_uuid()::text,
  alter column public_uid set not null;

create unique index if not exists profiles_public_uid_unique on public.profiles (public_uid);

-- Remove the earlier username-only experiment; UID is the editable identifier.
drop trigger if exists profiles_one_username_change on public.profiles;
drop trigger if exists profiles_sync_username_to_auth on public.profiles;
drop function if exists public.enforce_one_profile_username_change();
drop function if exists public.sync_profile_username_to_auth_user();

create or replace function public.enforce_one_profile_uid_change()
returns trigger
language plpgsql
as $$
begin
  if new.public_uid is distinct from old.public_uid then
    if old.public_uid_change_used then
      raise exception 'Public UID can only be changed once';
    end if;
    if new.public_uid !~ '^[A-Za-z0-9_-]{3,36}$' then
      raise exception 'Public UID must be 3 to 36 letters, numbers, underscores, or hyphens';
    end if;
    new.public_uid_change_used := true;
  elsif old.public_uid_change_used then
    -- Do not allow a client update to reset the one-time flag.
    new.public_uid_change_used := true;
  end if;
  return new;
end;
$$;

drop trigger if exists profiles_one_uid_change on public.profiles;
create trigger profiles_one_uid_change
  before update on public.profiles
  for each row execute function public.enforce_one_profile_uid_change();

-- Keep Supabase Auth metadata in sync, without changing the internal Auth UUID.
create or replace function public.sync_profile_uid_to_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update auth.users
  set raw_user_meta_data = jsonb_set(
    coalesce(raw_user_meta_data, '{}'::jsonb),
    '{public_uid}',
    to_jsonb(new.public_uid),
    true
  )
  where id = new.id;
  return new;
end;
$$;

drop trigger if exists profiles_sync_uid_to_auth on public.profiles;
create trigger profiles_sync_uid_to_auth
  after update of public_uid on public.profiles
  for each row
  when (old.public_uid is distinct from new.public_uid)
  execute function public.sync_profile_uid_to_auth_user();

drop trigger if exists profiles_insert_uid_to_auth on public.profiles;
create trigger profiles_insert_uid_to_auth
  after insert on public.profiles
  for each row execute function public.sync_profile_uid_to_auth_user();

-- Enable threaded replies and persistent image/GIF attachments on comments.
alter table public.comments
  add column if not exists parent_comment_id text,
  add column if not exists media_url text,
  add column if not exists media_type text;

-- Let signed-in users delete only their own comments and replies.
drop policy if exists "Users can delete own comments" on public.comments;
create policy "Users can delete own comments"
  on public.comments
  for delete
  to authenticated
  using (auth.uid() = user_id);

-- Store feed images and videos separately from profile pictures.
alter table public.posts
  add column if not exists media_url text,
  add column if not exists media_type text;

insert into storage.buckets (id, name, public, file_size_limit)
values ('post-media', 'post-media', true, 52428800)
on conflict (id) do update set public = true, file_size_limit = excluded.file_size_limit;

drop policy if exists "Public can view post media" on storage.objects;
create policy "Public can view post media"
  on storage.objects
  for select
  to public
  using (bucket_id = 'post-media');

drop policy if exists "Users upload own post media" on storage.objects;
create policy "Users upload own post media"
  on storage.objects
  for insert
  to authenticated
  with check (bucket_id = 'post-media' and (storage.foldername(name))[1] = auth.uid()::text);

-- Record each reward source so rerunning this migration cannot pay twice.
create table if not exists public.credit_rewards (
  source_type text not null check (source_type in ('post', 'comment')),
  source_id text not null,
  user_id uuid not null,
  amount numeric not null,
  created_at timestamptz not null default now(),
  primary key (source_type, source_id)
);
revoke all on table public.credit_rewards from anon, authenticated;

-- Pay existing posts/comments once when installing rewards for the first time.
with inserted_rewards as (
  insert into public.credit_rewards (source_type, source_id, user_id, amount)
  select 'post', p.id::text, p.user_id, 0.50 from public.posts p
  union all
  select 'comment', c.id::text, c.user_id,
    case when c.parent_comment_id is null or btrim(c.parent_comment_id) = '' then 0.10 else 0.05 end
  from public.comments c
  on conflict (source_type, source_id) do nothing
  returning user_id, amount
), reward_totals as (
  select user_id, sum(amount) as amount from inserted_rewards group by user_id
)
update public.profiles p
set credits = coalesce(p.credits, 0) + reward_totals.amount
from reward_totals
where p.id = reward_totals.user_id;

-- Award NEXUS credits once for each successfully created post.
create or replace function public.reward_new_post()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  recorded_source text;
begin
  insert into public.credit_rewards (source_type, source_id, user_id, amount)
  values ('post', new.id::text, new.user_id, 0.50)
  on conflict (source_type, source_id) do nothing
  returning source_id into recorded_source;
  if recorded_source is not null then
    update public.profiles set credits = coalesce(credits, 0) + 0.50 where id = new.user_id;
  end if;
  return new;
end;
$$;

drop trigger if exists posts_reward_author on public.posts;
create trigger posts_reward_author
  after insert on public.posts
  for each row execute function public.reward_new_post();

-- Award comments and replies at their requested rates.
create or replace function public.reward_new_comment()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  reward_amount numeric;
  recorded_source text;
begin
  reward_amount := case
    when new.parent_comment_id is null or btrim(new.parent_comment_id) = '' then 0.10
    else 0.05
  end;
  insert into public.credit_rewards (source_type, source_id, user_id, amount)
  values ('comment', new.id::text, new.user_id, reward_amount)
  on conflict (source_type, source_id) do nothing
  returning source_id into recorded_source;
  if recorded_source is not null then
    update public.profiles set credits = coalesce(credits, 0) + reward_amount where id = new.user_id;
  end if;
  return new;
end;
$$;

drop trigger if exists comments_reward_author on public.comments;
create trigger comments_reward_author
  after insert on public.comments
  for each row execute function public.reward_new_comment();
