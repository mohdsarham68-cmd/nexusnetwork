-- NEXUS Guilds: run in Supabase SQL Editor (safe to re-run for updates/repairs).
create extension if not exists pgcrypto;

create table if not exists public.guilds (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 48),
  description text not null default '' check (char_length(description) <= 300),
  logo_url text,
  owner_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);
create unique index if not exists guilds_name_lower_unique on public.guilds (lower(name));

create table if not exists public.guild_members (
  guild_id uuid not null references public.guilds(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  rank text not null default 'member' check (rank in ('owner','co-assistant','member')),
  created_at timestamptz not null default now(),
  primary key (guild_id,user_id)
);

create table if not exists public.guild_posts (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null references public.guilds(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  content text not null check (char_length(trim(content)) > 0),
  created_at timestamptz not null default now()
);
create index if not exists guild_posts_guild_created_idx on public.guild_posts(guild_id,created_at desc);

create table if not exists public.guild_post_reports (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null references public.guilds(id) on delete cascade,
  post_id uuid not null references public.guild_posts(id) on delete cascade,
  reporter_id uuid not null references public.profiles(id) on delete cascade,
  reason text not null check (char_length(trim(reason)) between 1 and 300),
  created_at timestamptz not null default now(),
  unique(post_id,reporter_id)
);

-- Ensure every guild has its owner in the roster, including guilds created before this repair.
create or replace function public.add_guild_creator_as_owner()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.guild_members(guild_id,user_id,rank)
  values(new.id,new.owner_id,'owner')
  on conflict(guild_id,user_id) do update set rank='owner';
  return new;
end $$;
drop trigger if exists guild_creator_membership on public.guilds;
create trigger guild_creator_membership after insert on public.guilds
for each row execute function public.add_guild_creator_as_owner();
update public.guild_members gm set rank='member'
from public.guilds g where gm.guild_id=g.id and gm.rank='owner' and gm.user_id<>g.owner_id;
insert into public.guild_members(guild_id,user_id,rank)
select id,owner_id,'owner' from public.guilds
on conflict(guild_id,user_id) do update set rank='owner';

alter table public.guilds enable row level security;
alter table public.guild_members enable row level security;
alter table public.guild_posts enable row level security;
alter table public.guild_post_reports enable row level security;

create or replace function public.is_guild_member(target_guild uuid)
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.guild_members where guild_id=target_guild and user_id=auth.uid()) $$;
create or replace function public.is_guild_owner(target_guild uuid)
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.guild_members where guild_id=target_guild and user_id=auth.uid() and rank='owner') $$;
create or replace function public.is_guild_coassistant(target_guild uuid)
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.guild_members where guild_id=target_guild and user_id=auth.uid() and rank='co-assistant') $$;
create or replace function public.is_guild_moderator(target_guild uuid)
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.guild_members where guild_id=target_guild and user_id=auth.uid() and rank in ('owner','co-assistant')) $$;
revoke all on function public.is_guild_member(uuid) from public;
revoke all on function public.is_guild_owner(uuid) from public;
revoke all on function public.is_guild_coassistant(uuid) from public;
revoke all on function public.is_guild_moderator(uuid) from public;
grant execute on function public.is_guild_member(uuid) to authenticated;
grant execute on function public.is_guild_owner(uuid) to authenticated;
grant execute on function public.is_guild_coassistant(uuid) to authenticated;
grant execute on function public.is_guild_moderator(uuid) to authenticated;

create or replace function public.transfer_guild_ownership(target_guild uuid, next_owner uuid)
returns boolean language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_guild_owner(target_guild) then raise exception 'Only the current owner can transfer this guild'; end if;
  if next_owner=auth.uid() or not exists(select 1 from public.guild_members where guild_id=target_guild and user_id=next_owner) then raise exception 'The new owner must already be another guild member'; end if;
  update public.guild_members set rank='member' where guild_id=target_guild and user_id=auth.uid();
  update public.guild_members set rank='owner' where guild_id=target_guild and user_id=next_owner;
  update public.guilds set owner_id=next_owner where id=target_guild;
  return true;
end $$;
revoke all on function public.transfer_guild_ownership(uuid,uuid) from public;
grant execute on function public.transfer_guild_ownership(uuid,uuid) to authenticated;

drop policy if exists "Guilds are searchable by signed-in users" on public.guilds;
create policy "Guilds are searchable by signed-in users" on public.guilds for select to authenticated using (true);
drop policy if exists "Signed-in users create guilds" on public.guilds;
create policy "Signed-in users create guilds" on public.guilds for insert to authenticated with check (owner_id=auth.uid());
drop policy if exists "Guild owners edit their guild" on public.guilds;
create policy "Guild owners edit their guild" on public.guilds for update to authenticated using (public.is_guild_owner(id)) with check (public.is_guild_owner(id) and owner_id=auth.uid());
drop policy if exists "Guild owners delete their guild" on public.guilds;
create policy "Guild owners delete their guild" on public.guilds for delete to authenticated using (public.is_guild_owner(id));

drop policy if exists "Members can see guild rosters" on public.guild_members;
create policy "Members can see guild rosters" on public.guild_members for select to authenticated using (user_id=auth.uid() or public.is_guild_member(guild_id));
drop policy if exists "Users join guilds as members" on public.guild_members;
create policy "Users join guilds as members" on public.guild_members for insert to authenticated with check (
  (user_id=auth.uid() and rank='member') or
  (user_id=auth.uid() and rank='owner' and exists(select 1 from public.guilds where id=guild_id and owner_id=auth.uid()))
);
drop policy if exists "Owners manage guild ranks" on public.guild_members;
drop policy if exists "Owners manage ranks and co-assistants remove members" on public.guild_members;
create policy "Owners manage ranks and co-assistants remove members" on public.guild_members for update to authenticated using (public.is_guild_owner(guild_id) and user_id<>auth.uid()) with check (rank in ('co-assistant','member') and user_id<>auth.uid());
drop policy if exists "Members leave or owners remove members" on public.guild_members;
drop policy if exists "Members leave or moderators remove members" on public.guild_members;
create policy "Members leave or moderators remove members" on public.guild_members for delete to authenticated using (
  (user_id=auth.uid() and rank<>'owner') or
  (public.is_guild_owner(guild_id) and user_id<>auth.uid()) or
  (public.is_guild_coassistant(guild_id) and rank='member' and user_id<>auth.uid())
);

drop policy if exists "Only guild members read private posts" on public.guild_posts;
create policy "Only guild members read private posts" on public.guild_posts for select to authenticated using (public.is_guild_member(guild_id));
drop policy if exists "Guild members publish private posts" on public.guild_posts;
create policy "Guild members publish private posts" on public.guild_posts for insert to authenticated with check (user_id=auth.uid() and public.is_guild_member(guild_id));
drop policy if exists "Authors or guild owners delete posts" on public.guild_posts;
drop policy if exists "Authors or guild moderators delete posts" on public.guild_posts;
create policy "Authors or guild moderators delete posts" on public.guild_posts for delete to authenticated using (user_id=auth.uid() or public.is_guild_moderator(guild_id));
drop policy if exists "Members report guild posts" on public.guild_post_reports;
create policy "Members report guild posts" on public.guild_post_reports for insert to authenticated with check (reporter_id=auth.uid() and public.is_guild_member(guild_id));
drop policy if exists "Guild moderators review post reports" on public.guild_post_reports;
create policy "Guild moderators review post reports" on public.guild_post_reports for select to authenticated using (public.is_guild_moderator(guild_id));
drop policy if exists "Guild moderators dismiss post reports" on public.guild_post_reports;
create policy "Guild moderators dismiss post reports" on public.guild_post_reports for delete to authenticated using (public.is_guild_moderator(guild_id));

insert into storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
values ('guild-logos','guild-logos',true,3145728,array['image/png','image/jpeg','image/webp','image/gif'])
on conflict (id) do update set public=true,file_size_limit=3145728,allowed_mime_types=array['image/png','image/jpeg','image/webp','image/gif'];
drop policy if exists "Guild logo images are public" on storage.objects;
create policy "Guild logo images are public" on storage.objects for select using (bucket_id='guild-logos');
drop policy if exists "Signed-in users upload guild logos" on storage.objects;
create policy "Signed-in users upload guild logos" on storage.objects for insert to authenticated with check (bucket_id='guild-logos' and (storage.foldername(name))[2]=auth.uid()::text);
drop policy if exists "Owners update guild logos" on storage.objects;
create policy "Owners update guild logos" on storage.objects for update to authenticated using (bucket_id='guild-logos' and (storage.foldername(name))[2]=auth.uid()::text) with check (bucket_id='guild-logos' and (storage.foldername(name))[2]=auth.uid()::text);
