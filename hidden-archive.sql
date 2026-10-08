-- Hidden Archieve PDF library. Run once in the Supabase SQL Editor.
-- Authenticated members can browse and open archived PDFs; members can add
-- documents and delete only the documents they uploaded.

create table if not exists public.archive_documents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 120),
  original_name text not null,
  storage_path text not null unique,
  created_at timestamptz not null default now()
);

alter table public.archive_documents enable row level security;
revoke all on table public.archive_documents from anon;
grant select, insert, delete on table public.archive_documents to authenticated;
grant update on table public.archive_documents to authenticated;

drop policy if exists "Authenticated users can browse archive metadata" on public.archive_documents;
create policy "Authenticated users can browse archive metadata"
  on public.archive_documents for select to authenticated using (true);

drop policy if exists "Members can add their own archive documents" on public.archive_documents;
create policy "Members can add their own archive documents"
  on public.archive_documents for insert to authenticated with check (user_id = (select auth.uid()));

drop policy if exists "Members can delete their own archive documents" on public.archive_documents;
create policy "Members can delete their own archive documents"
  on public.archive_documents for delete to authenticated using (user_id = (select auth.uid()));

drop policy if exists "Members can update their own archive documents" on public.archive_documents;
create policy "Members can update their own archive documents"
  on public.archive_documents for update to authenticated using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create table if not exists public.archive_document_ratings (
  document_id uuid not null references public.archive_documents(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  value smallint not null check (value in (-1, 1)),
  created_at timestamptz not null default now(),
  primary key (document_id, user_id)
);

alter table public.archive_document_ratings enable row level security;
revoke all on table public.archive_document_ratings from anon;
grant select, insert, update, delete on table public.archive_document_ratings to authenticated;

drop policy if exists "Authenticated users can browse archive ratings" on public.archive_document_ratings;
create policy "Authenticated users can browse archive ratings"
  on public.archive_document_ratings for select to authenticated using (true);

drop policy if exists "Members can rate archive documents as themselves" on public.archive_document_ratings;
create policy "Members can rate archive documents as themselves"
  on public.archive_document_ratings for insert to authenticated with check (user_id = (select auth.uid()));

drop policy if exists "Members can update their own archive ratings" on public.archive_document_ratings;
create policy "Members can update their own archive ratings"
  on public.archive_document_ratings for update to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

drop policy if exists "Members can remove their own archive ratings" on public.archive_document_ratings;
create policy "Members can remove their own archive ratings"
  on public.archive_document_ratings for delete to authenticated using (user_id = (select auth.uid()));

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('hidden-archive', 'hidden-archive', false, 20971520, array['application/pdf'])
on conflict (id) do update set
  public = false,
  file_size_limit = 20971520,
  allowed_mime_types = array['application/pdf'];

drop policy if exists "Authenticated users can open archive PDFs" on storage.objects;
create policy "Authenticated users can open archive PDFs"
  on storage.objects for select to authenticated using (bucket_id = 'hidden-archive');

drop policy if exists "Members can upload PDFs to their archive folder" on storage.objects;
create policy "Members can upload PDFs to their archive folder"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'hidden-archive' and (storage.foldername(name))[1] = (select auth.uid())::text);

drop policy if exists "Members can delete PDFs from their archive folder" on storage.objects;
create policy "Members can delete PDFs from their archive folder"
  on storage.objects for delete to authenticated
  using (bucket_id = 'hidden-archive' and (storage.foldername(name))[1] = (select auth.uid())::text);
