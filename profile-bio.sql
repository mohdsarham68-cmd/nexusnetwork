-- Add the profile bio field used by the NEXUS profile editor.
alter table public.profiles
  add column if not exists bio text;

-- Refresh the PostgREST schema cache so the browser client can use the new field.
notify pgrst, 'reload schema';
