-- CatatHutang Profesional: Supabase setup / upgrade SQL
-- Aman dijalankan ulang. Mendukung hash SHA-256 versi lama lalu migrasi otomatis ke bcrypt saat PIN benar.

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.debt_sync_store (
  account_id text primary key,
  pin_salt text not null default '',
  pin_hash text not null,
  pin_scheme text not null default 'sha256',
  failed_attempts integer not null default 0,
  locked_until timestamptz,
  payload jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now(),
  constraint debt_sync_payload_is_array check (jsonb_typeof(payload) = 'array')
);

-- Tambahkan kolom tanpa menghapus data pada instalasi versi sebelumnya.
alter table public.debt_sync_store add column if not exists pin_scheme text not null default 'sha256';
alter table public.debt_sync_store add column if not exists failed_attempts integer not null default 0;
alter table public.debt_sync_store add column if not exists locked_until timestamptz;
alter table public.debt_sync_store alter column pin_salt set default '';

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
  v_attempts integer;
  v_matches boolean := false;
begin
  if p_account_id is null or pg_catalog.length(pg_catalog.btrim(p_account_id)) < 3
     or p_pin is null or pg_catalog.length(p_pin) < 8 or pg_catalog.length(p_pin) > 128 then
    raise exception 'ID_DATABASE_ATAU_PIN_TIDAK_VALID';
  end if;

  select * into v_row
  from public.debt_sync_store
  where account_id = pg_catalog.btrim(p_account_id)
  for update;

  if not found then
    return pg_catalog.jsonb_build_object('ok', true, 'exists', false, 'data', '[]'::jsonb, 'updated_at', null);
  end if;

  if v_row.locked_until is not null and v_row.locked_until > pg_catalog.now() then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'DATABASE_LOCKED', 'locked_until', v_row.locked_until);
  end if;

  if v_row.locked_until is not null and v_row.locked_until <= pg_catalog.now() then
    v_row.failed_attempts := 0;
  end if;

  if v_row.pin_scheme = 'bcrypt' then
    v_matches := extensions.crypt(p_pin, v_row.pin_hash) = v_row.pin_hash;
  else
    -- Kompatibilitas dengan hash SHA-256 yang dipakai SQL versi sebelumnya.
    v_matches := v_row.pin_hash = pg_catalog.encode(extensions.digest(p_pin || v_row.pin_salt, 'sha256'), 'hex');
  end if;

  if not v_matches then
    v_attempts := v_row.failed_attempts + 1;
    update public.debt_sync_store
    set failed_attempts = v_attempts,
        locked_until = case when v_attempts >= 5 then pg_catalog.now() + interval '15 minutes' else null end
    where account_id = pg_catalog.btrim(p_account_id);
    return pg_catalog.jsonb_build_object(
      'ok', false,
      'error', case when v_attempts >= 5 then 'DATABASE_LOCKED' else 'PIN_DATABASE_SALAH' end,
      'remaining_attempts', greatest(0, 5 - v_attempts)
    );
  end if;

  -- PIN benar: reset pembatasan dan migrasikan hash lama ke bcrypt.
  if v_row.pin_scheme <> 'bcrypt' then
    update public.debt_sync_store
    set pin_hash = extensions.crypt(p_pin, extensions.gen_salt('bf', 12)),
        pin_scheme = 'bcrypt',
        pin_salt = '',
        failed_attempts = 0,
        locked_until = null
    where account_id = pg_catalog.btrim(p_account_id);
  else
    update public.debt_sync_store
    set failed_attempts = 0, locked_until = null
    where account_id = pg_catalog.btrim(p_account_id)
      and (failed_attempts <> 0 or locked_until is not null);
  end if;

  return pg_catalog.jsonb_build_object('ok', true, 'exists', true, 'data', v_row.payload, 'updated_at', v_row.updated_at);
end;
$$;

create or replace function public.debt_save(p_account_id text, p_pin text, p_payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_row public.debt_sync_store%rowtype;
  v_attempts integer;
  v_matches boolean := false;
  v_time timestamptz;
begin
  if p_account_id is null or pg_catalog.length(pg_catalog.btrim(p_account_id)) < 3
     or p_pin is null or pg_catalog.length(p_pin) < 8 or pg_catalog.length(p_pin) > 128 then
    raise exception 'ID_DATABASE_ATAU_PIN_TIDAK_VALID';
  end if;
  if p_payload is null or pg_catalog.jsonb_typeof(p_payload) <> 'array' then
    raise exception 'FORMAT_DATA_HARUS_ARRAY';
  end if;
  if pg_catalog.pg_column_size(p_payload) > 2000000 then
    raise exception 'UKURAN_DATA_TERLALU_BESAR';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(pg_catalog.btrim(p_account_id), 0));
  select * into v_row
  from public.debt_sync_store
  where account_id = pg_catalog.btrim(p_account_id)
  for update;

  if not found then
    insert into public.debt_sync_store(account_id, pin_salt, pin_hash, pin_scheme, failed_attempts, payload, updated_at)
    values (
      pg_catalog.btrim(p_account_id),
      '',
      extensions.crypt(p_pin, extensions.gen_salt('bf', 12)),
      'bcrypt',
      0,
      p_payload,
      pg_catalog.now()
    )
    returning updated_at into v_time;
    return pg_catalog.jsonb_build_object('ok', true, 'updated_at', v_time);
  end if;

  if v_row.locked_until is not null and v_row.locked_until > pg_catalog.now() then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'DATABASE_LOCKED', 'locked_until', v_row.locked_until);
  end if;

  if v_row.pin_scheme = 'bcrypt' then
    v_matches := extensions.crypt(p_pin, v_row.pin_hash) = v_row.pin_hash;
  else
    v_matches := v_row.pin_hash = pg_catalog.encode(extensions.digest(p_pin || v_row.pin_salt, 'sha256'), 'hex');
  end if;

  if not v_matches then
    v_attempts := case when v_row.locked_until is not null and v_row.locked_until <= pg_catalog.now() then 1 else v_row.failed_attempts + 1 end;
    update public.debt_sync_store
    set failed_attempts = v_attempts,
        locked_until = case when v_attempts >= 5 then pg_catalog.now() + interval '15 minutes' else null end
    where account_id = pg_catalog.btrim(p_account_id);
    return pg_catalog.jsonb_build_object(
      'ok', false,
      'error', case when v_attempts >= 5 then 'DATABASE_LOCKED' else 'PIN_DATABASE_SALAH' end,
      'remaining_attempts', greatest(0, 5 - v_attempts)
    );
  end if;

  update public.debt_sync_store
  set payload = p_payload,
      pin_hash = case when v_row.pin_scheme = 'bcrypt' then v_row.pin_hash else extensions.crypt(p_pin, extensions.gen_salt('bf', 12)) end,
      pin_scheme = 'bcrypt',
      pin_salt = '',
      failed_attempts = 0,
      locked_until = null,
      updated_at = pg_catalog.now()
  where account_id = pg_catalog.btrim(p_account_id)
  returning updated_at into v_time;

  return pg_catalog.jsonb_build_object('ok', true, 'updated_at', v_time);
end;
$$;

revoke all on function public.debt_get(text, text) from public;
revoke all on function public.debt_save(text, text, jsonb) from public;
grant execute on function public.debt_get(text, text) to anon, authenticated;
grant execute on function public.debt_save(text, text, jsonb) to anon, authenticated;

-- Data hanya dapat dibaca/ditulis melalui fungsi RPC yang memeriksa PIN.
