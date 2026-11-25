create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.debt_sync_store (
  account_id text primary key,
  pin_salt text not null,
  pin_hash text not null,
  payload jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now(),
  constraint debt_sync_payload_is_array check (jsonb_typeof(payload) = 'array')
);

alter table public.debt_sync_store enable row level security;
revoke all on table public.debt_sync_store from anon, authenticated;
grant usage on schema public to anon, authenticated;

create or replace function public.debt_get(p_account_id text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_row public.debt_sync_store%rowtype;
begin
  if p_account_id is null or pg_catalog.length(pg_catalog.btrim(p_account_id)) < 3 or p_pin is null or pg_catalog.length(p_pin) < 8 then
    raise exception 'ID_DATABASE_ATAU_PIN_TIDAK_VALID';
  end if;
  select * into v_row from public.debt_sync_store where account_id = p_account_id;
  if not found then
    return pg_catalog.jsonb_build_object('exists', false, 'data', '[]'::jsonb, 'updated_at', null);
  end if;
  if v_row.pin_hash <> pg_catalog.encode(extensions.digest(p_pin || v_row.pin_salt, 'sha256'), 'hex') then
    raise exception 'PIN_DATABASE_SALAH';
  end if;
  return pg_catalog.jsonb_build_object('exists', true, 'data', v_row.payload, 'updated_at', v_row.updated_at);
end;
$$;

create or replace function public.debt_save(p_account_id text, p_pin text, p_payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash text;
  v_salt text;
  v_time timestamptz;
begin
  if p_account_id is null or pg_catalog.length(pg_catalog.btrim(p_account_id)) < 3 or p_pin is null or pg_catalog.length(p_pin) < 8 then
    raise exception 'ID_DATABASE_ATAU_PIN_TIDAK_VALID';
  end if;
  if p_payload is null or pg_catalog.jsonb_typeof(p_payload) <> 'array' then
    raise exception 'FORMAT_DATA_HARUS_ARRAY';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_account_id, 0));
  select pin_hash, pin_salt into v_hash, v_salt from public.debt_sync_store where account_id = p_account_id for update;
  if not found then
    v_salt := pg_catalog.encode(extensions.gen_random_bytes(16), 'hex');
    insert into public.debt_sync_store(account_id, pin_salt, pin_hash, payload, updated_at)
    values (p_account_id, v_salt, pg_catalog.encode(extensions.digest(p_pin || v_salt, 'sha256'), 'hex'), p_payload, pg_catalog.now())
    returning updated_at into v_time;
  else
    if v_hash <> pg_catalog.encode(extensions.digest(p_pin || v_salt, 'sha256'), 'hex') then
      raise exception 'PIN_DATABASE_SALAH';
    end if;
    update public.debt_sync_store set payload = p_payload, updated_at = pg_catalog.now()
      where account_id = p_account_id returning updated_at into v_time;
  end if;
  return pg_catalog.jsonb_build_object('ok', true, 'updated_at', v_time);
end;
$$;

revoke all on function public.debt_get(text, text) from public;
revoke all on function public.debt_save(text, text, jsonb) from public;
grant execute on function public.debt_get(text, text) to anon, authenticated;
grant execute on function public.debt_save(text, text, jsonb) to anon, authenticated;
