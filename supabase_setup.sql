-- Smart Resume Maker Pro 5.0 — Supabase database setup
-- Run this entire script in Supabase Dashboard → SQL Editor → New query.
-- This design intentionally does NOT allow anonymous direct table reads.
-- Public viewers can read only a matching, currently-enabled share token via RPC.

create extension if not exists pgcrypto;

create table if not exists public.resumes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null default 'Untitled Resume',
  resume_data jsonb not null default '{}'::jsonb,
  share_token text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists resumes_user_id_idx on public.resumes(user_id);
create index if not exists resumes_share_token_idx on public.resumes(share_token)
  where share_token is not null;

alter table public.resumes enable row level security;

-- Remove any earlier policies with these names so this script can be rerun.
drop policy if exists "Owners can view their resumes" on public.resumes;
drop policy if exists "Owners can insert their resumes" on public.resumes;
drop policy if exists "Owners can update their resumes" on public.resumes;
drop policy if exists "Owners can delete their resumes" on public.resumes;

create policy "Owners can view their resumes"
on public.resumes for select to authenticated
using (auth.uid() = user_id);

create policy "Owners can insert their resumes"
on public.resumes for insert to authenticated
with check (auth.uid() = user_id);

create policy "Owners can update their resumes"
on public.resumes for update to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

create policy "Owners can delete their resumes"
on public.resumes for delete to authenticated
using (auth.uid() = user_id);

-- Grant table operations only to signed-in users; RLS limits them to their own rows.
grant select, insert, update, delete on public.resumes to authenticated;
revoke all on public.resumes from anon;

-- Safe public sharing endpoint: returns only the resume matching an active token.
-- It does not expose a table-wide public SELECT policy.
create or replace function public.get_shared_resume(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  result jsonb;
begin
  if p_token is null or length(p_token) < 40 or length(p_token) > 128 then
    return null;
  end if;

  select jsonb_build_object(
    'title', r.title,
    'resume_data', r.resume_data
  )
  into result
  from public.resumes as r
  where r.share_token = p_token
  limit 1;

  return result;
end;
$$;

revoke all on function public.get_shared_resume(text) from public;
grant execute on function public.get_shared_resume(text) to anon, authenticated;

-- Optional: enable email/password auth in Supabase Authentication settings.
-- For a first test, you may temporarily disable email confirmation in
-- Authentication → Providers → Email. Re-enable it for a public production app.
