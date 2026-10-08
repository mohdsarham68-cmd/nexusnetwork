-- NEXUS rewards: $0.50 per post, $0.10 per top-level comment, $0.05 per reply.
-- Safe to run again; existing balances are retained.

alter table public.profiles
  add column if not exists credits numeric not null default 0;

alter table public.comments
  add column if not exists parent_comment_id text;

create table if not exists public.credit_rewards (
  source_type text not null check (source_type in ('post', 'comment')),
  source_id text not null,
  user_id uuid not null,
  amount numeric not null,
  created_at timestamptz not null default now(),
  primary key (source_type, source_id)
);
revoke all on table public.credit_rewards from anon, authenticated;

-- Backfill previous activity once; rerunning this script cannot pay it twice.
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
