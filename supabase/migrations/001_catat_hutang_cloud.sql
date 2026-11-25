-- CatatHutang Cloud v3
-- Jalankan SATU KALI di Supabase > SQL Editor pada project yang sama.

create extension if not exists pgcrypto;

create table if not exists public.ledger_accounts (
  id uuid primary key default gen_random_uuid(),
  account_code text not null unique,
  auth_user_id uuid not null unique references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.debt_records (
  id uuid not null,
  account_id uuid not null references public.ledger_accounts(id) on delete cascade,
  phone_key text not null,
  data jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (account_id, id),
  constraint debt_records_account_phone_unique unique (account_id, phone_key)
);
create index if not exists debt_records_account_created_idx
  on public.debt_records(account_id, created_at asc);

create table if not exists public.debt_backups (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references public.ledger_accounts(id) on delete cascade,
  created_at timestamptz not null default now(),
  record_count integer not null default 0,
  records jsonb not null default '[]'::jsonb
);
create index if not exists debt_backups_account_created_idx
  on public.debt_backups(account_id, created_at desc);

alter table public.ledger_accounts enable row level security;
alter table public.debt_records enable row level security;
alter table public.debt_backups enable row level security;

drop policy if exists ledger_accounts_read_own on public.ledger_accounts;
create policy ledger_accounts_read_own on public.ledger_accounts
  for select to authenticated
  using (auth_user_id = (select auth.uid()));

drop policy if exists debt_records_read_own on public.debt_records;
create policy debt_records_read_own on public.debt_records
  for select to authenticated
  using (exists (
    select 1 from public.ledger_accounts a
    where a.id = debt_records.account_id and a.auth_user_id = (select auth.uid())
  ));

drop policy if exists debt_backups_read_own on public.debt_backups;
create policy debt_backups_read_own on public.debt_backups
  for select to authenticated
  using (exists (
    select 1 from public.ledger_accounts a
    where a.id = debt_backups.account_id and a.auth_user_id = (select auth.uid())
  ));

revoke all on table public.ledger_accounts from anon, authenticated;
revoke all on table public.debt_records from anon, authenticated;
revoke all on table public.debt_backups from anon, authenticated;
grant select on table public.ledger_accounts, public.debt_records, public.debt_backups to authenticated;

create or replace function public._catatan_snapshot(p_account_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or not exists (
    select 1 from public.ledger_accounts
    where id = p_account_id and auth_user_id = auth.uid()
  ) then
    raise exception 'Akses akun ditolak';
  end if;

  insert into public.debt_backups(account_id, record_count, records)
  select p_account_id,
         count(*)::integer,
         coalesce(jsonb_agg(jsonb_build_object(
           'id', d.id,
           'phone_key', d.phone_key,
           'data', d.data,
           'created_at', d.created_at,
           'updated_at', d.updated_at
         ) order by d.created_at asc), '[]'::jsonb)
  from public.debt_records d
  where d.account_id = p_account_id
  having count(*) > 0;

  delete from public.debt_backups b
  where b.account_id = p_account_id
    and b.id not in (
      select id from public.debt_backups
      where account_id = p_account_id
      order by created_at desc
      limit 12
    );
end;
$$;

create or replace function public.create_debt_customer(p_data jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account_id uuid;
  v_id uuid;
  v_phone_key text;
  v_row public.debt_records%rowtype;
begin
  select id into v_account_id from public.ledger_accounts where auth_user_id = auth.uid();
  if v_account_id is null then raise exception 'Akun belum terhubung'; end if;
  if jsonb_typeof(p_data) <> 'object' then raise exception 'Format pelanggan tidak valid'; end if;

  v_id := coalesce(nullif(p_data->>'id','')::uuid, gen_random_uuid());
  v_phone_key := regexp_replace(coalesce(p_data->>'phoneKey',''), '[^0-9]', '', 'g');
  if length(v_phone_key) < 8 then raise exception 'Nomor telepon tidak valid'; end if;
  if coalesce(p_data->>'name','') = '' then raise exception 'Nama pelanggan wajib diisi'; end if;

  perform public._catatan_snapshot(v_account_id);
  insert into public.debt_records as current_record(id, account_id, phone_key, data)
  values (v_id, v_account_id, v_phone_key, p_data)
  on conflict (account_id, phone_key) do update
  set data = current_record.data || jsonb_build_object(
        'items', coalesce(current_record.data->'items','[]'::jsonb) || coalesce(excluded.data->'items','[]'::jsonb),
        'total', coalesce((current_record.data->>'total')::numeric,0) + coalesce((excluded.data->>'total')::numeric,0),
        'paid', coalesce((current_record.data->>'paid')::numeric,0) + coalesce((excluded.data->>'paid')::numeric,0),
        'payments', coalesce(current_record.data->'payments','[]'::jsonb) || coalesce(excluded.data->'payments','[]'::jsonb),
        'note', coalesce(nullif(excluded.data->>'note',''), current_record.data->>'note', ''),
        'updatedAt', now()
      ),
      updated_at = now()
  returning * into v_row;

  return jsonb_build_object('id', v_row.id, 'merged', (v_row.id <> v_id), 'data', v_row.data);
end;
$$;

create or replace function public.update_debt_customer(p_data jsonb, p_expected_updated_at timestamptz)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account_id uuid;
  v_id uuid;
  v_phone_key text;
  v_row public.debt_records%rowtype;
  v_current_updated_at timestamptz;
begin
  select id into v_account_id from public.ledger_accounts where auth_user_id = auth.uid();
  if v_account_id is null then raise exception 'Akun belum terhubung'; end if;
  v_id := (p_data->>'id')::uuid;
  v_phone_key := regexp_replace(coalesce(p_data->>'phoneKey',''), '[^0-9]', '', 'g');
  if length(v_phone_key) < 8 then raise exception 'Nomor telepon tidak valid'; end if;

  select updated_at into v_current_updated_at from public.debt_records where account_id=v_account_id and id=v_id for update;
  if not found then raise exception 'Pelanggan tidak ditemukan atau sudah berubah'; end if;
  if p_expected_updated_at is null or v_current_updated_at <> p_expected_updated_at then
    raise exception 'Data pelanggan baru saja diubah dari perangkat lain. Muat ulang data, lalu ulangi edit.';
  end if;
  if exists (select 1 from public.debt_records where account_id=v_account_id and phone_key=v_phone_key and id<>v_id) then
    raise exception 'Nomor tersebut sudah digunakan pelanggan lain';
  end if;

  perform public._catatan_snapshot(v_account_id);
  update public.debt_records
  set phone_key=v_phone_key, data=p_data, updated_at=now()
  where account_id=v_account_id and id=v_id
  returning * into v_row;
  return jsonb_build_object('id',v_row.id,'data',v_row.data);
end;
$$;

create or replace function public.add_debt_payment(p_id uuid, p_amount bigint)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account_id uuid;
  v_data jsonb;
  v_total numeric;
  v_paid numeric;
  v_next_paid numeric;
  v_payment jsonb;
begin
  select id into v_account_id from public.ledger_accounts where auth_user_id=auth.uid();
  if v_account_id is null then raise exception 'Akun belum terhubung'; end if;
  if p_amount is null or p_amount <= 0 then raise exception 'Nominal pembayaran harus lebih dari nol'; end if;

  select data into v_data from public.debt_records
  where account_id=v_account_id and id=p_id for update;
  if not found then raise exception 'Pelanggan tidak ditemukan'; end if;

  v_total := coalesce((v_data->>'total')::numeric,0);
  v_paid := coalesce((v_data->>'paid')::numeric,0);
  if p_amount > v_total-v_paid then raise exception 'Pembayaran melebihi sisa hutang'; end if;
  v_next_paid := v_paid + p_amount;
  perform public._catatan_snapshot(v_account_id);
  v_payment := jsonb_build_object('id',gen_random_uuid()::text,'amount',p_amount,'date',now());

  if v_next_paid >= v_total then
    delete from public.debt_records where account_id=v_account_id and id=p_id;
    return jsonb_build_object('deleted',true,'paid',v_next_paid);
  end if;

  update public.debt_records
  set data = v_data || jsonb_build_object(
        'paid',v_next_paid,
        'payments',coalesce(v_data->'payments','[]'::jsonb) || jsonb_build_array(v_payment),
        'updatedAt',now()
      ),
      updated_at=now()
  where account_id=v_account_id and id=p_id;
  return jsonb_build_object('deleted',false,'paid',v_next_paid);
end;
$$;

create or replace function public.delete_debt_customer(p_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare v_account_id uuid;
begin
  select id into v_account_id from public.ledger_accounts where auth_user_id=auth.uid();
  if v_account_id is null then raise exception 'Akun belum terhubung'; end if;
  if not exists(select 1 from public.debt_records where account_id=v_account_id and id=p_id) then
    raise exception 'Pelanggan tidak ditemukan';
  end if;
  perform public._catatan_snapshot(v_account_id);
  delete from public.debt_records where account_id=v_account_id and id=p_id;
  return true;
end;
$$;

create or replace function public.replace_debt_records(p_records jsonb)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account_id uuid;
  v_item jsonb;
  v_count integer := 0;
  v_id uuid;
  v_phone_key text;
begin
  select id into v_account_id from public.ledger_accounts where auth_user_id=auth.uid();
  if v_account_id is null then raise exception 'Akun belum terhubung'; end if;
  if jsonb_typeof(p_records) <> 'array' then raise exception 'File cadangan tidak berisi daftar pelanggan'; end if;
  if jsonb_array_length(p_records) > 10000 then raise exception 'Cadangan terlalu besar'; end if;
  perform public._catatan_snapshot(v_account_id);
  delete from public.debt_records where account_id=v_account_id;

  for v_item in select value from jsonb_array_elements(p_records)
  loop
    v_id := coalesce(nullif(v_item->>'id','')::uuid,gen_random_uuid());
    v_phone_key := regexp_replace(coalesce(v_item->>'phoneKey',''), '[^0-9]', '', 'g');
    if length(v_phone_key) < 8 then raise exception 'Ada nomor pelanggan yang tidak valid dalam cadangan'; end if;
    insert into public.debt_records(id,account_id,phone_key,data)
    values(v_id,v_account_id,v_phone_key,v_item);
    v_count := v_count + 1;
  end loop;
  return v_count;
end;
$$;

create or replace function public.restore_debt_backup(p_backup_id uuid)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account_id uuid;
  v_records jsonb;
  v_item jsonb;
  v_count integer := 0;
begin
  select id into v_account_id from public.ledger_accounts where auth_user_id=auth.uid();
  if v_account_id is null then raise exception 'Akun belum terhubung'; end if;
  select records into v_records from public.debt_backups
    where id=p_backup_id and account_id=v_account_id;
  if v_records is null then raise exception 'Cadangan tidak ditemukan'; end if;

  perform public._catatan_snapshot(v_account_id);
  delete from public.debt_records where account_id=v_account_id;
  for v_item in select value from jsonb_array_elements(v_records)
  loop
    insert into public.debt_records(id,account_id,phone_key,data,created_at,updated_at)
    values(
      (v_item->>'id')::uuid,
      v_account_id,
      coalesce(v_item->>'phone_key',regexp_replace(coalesce(v_item->'data'->>'phoneKey',''),'[^0-9]','','g')),
      v_item->'data',
      coalesce((v_item->>'created_at')::timestamptz,now()),
      coalesce((v_item->>'updated_at')::timestamptz,now())
    );
    v_count := v_count+1;
  end loop;
  return v_count;
end;
$$;

revoke all on function public._catatan_snapshot(uuid) from public, anon, authenticated;
revoke all on function public.create_debt_customer(jsonb) from public, anon;
revoke all on function public.update_debt_customer(jsonb,timestamptz) from public, anon;
revoke all on function public.add_debt_payment(uuid,bigint) from public, anon;
revoke all on function public.delete_debt_customer(uuid) from public, anon;
revoke all on function public.replace_debt_records(jsonb) from public, anon;
revoke all on function public.restore_debt_backup(uuid) from public, anon;
grant execute on function public.create_debt_customer(jsonb) to authenticated;
grant execute on function public.update_debt_customer(jsonb,timestamptz) to authenticated;
grant execute on function public.add_debt_payment(uuid,bigint) to authenticated;
grant execute on function public.delete_debt_customer(uuid) to authenticated;
grant execute on function public.replace_debt_records(jsonb) to authenticated;
grant execute on function public.restore_debt_backup(uuid) to authenticated;

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime' and schemaname='public' and tablename='debt_records'
  ) then
    alter publication supabase_realtime add table public.debt_records;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime' and schemaname='public' and tablename='debt_backups'
  ) then
    alter publication supabase_realtime add table public.debt_backups;
  end if;
end $$;

alter table public.debt_records replica identity full;
alter table public.debt_backups replica identity full;

-- Rate limit login: maksimal 10 percobaan per akun dalam jendela 15 menit.
create table if not exists public.catatan_login_rate_limits (
  account_code text primary key,
  window_started_at timestamptz not null default now(),
  attempts integer not null default 0,
  blocked_until timestamptz
);
alter table public.catatan_login_rate_limits enable row level security;
revoke all on table public.catatan_login_rate_limits from anon, authenticated;

create or replace function public.catatan_check_login_rate(p_account_code text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.catatan_login_rate_limits%rowtype;
begin
  insert into public.catatan_login_rate_limits(account_code)
  values(p_account_code)
  on conflict(account_code) do nothing;

  select * into v_row from public.catatan_login_rate_limits
  where account_code=p_account_code for update;

  if v_row.blocked_until is not null and v_row.blocked_until > now() then
    return false;
  end if;

  if v_row.window_started_at < now() - interval '15 minutes' then
    update public.catatan_login_rate_limits
      set window_started_at=now(), attempts=1, blocked_until=null
      where account_code=p_account_code;
    return true;
  end if;

  if v_row.attempts >= 10 then
    update public.catatan_login_rate_limits
      set blocked_until=now() + interval '15 minutes'
      where account_code=p_account_code;
    return false;
  end if;

  update public.catatan_login_rate_limits
    set attempts=attempts+1
    where account_code=p_account_code;
  return true;
end;
$$;

create or replace function public.catatan_clear_login_rate(p_account_code text)
returns void
language sql
security definer
set search_path = public
as $$
  update public.catatan_login_rate_limits
  set window_started_at=now(), attempts=0, blocked_until=null
  where account_code=p_account_code;
$$;

revoke all on function public.catatan_check_login_rate(text) from public, anon, authenticated;
revoke all on function public.catatan_clear_login_rate(text) from public, anon, authenticated;
grant execute on function public.catatan_check_login_rate(text) to service_role;
grant execute on function public.catatan_clear_login_rate(text) to service_role;

-- Catat Hutang Cloud v3 - patch izin backend + diagnostik database.
-- Aman dijalankan berulang kali. Tidak menghapus data, tabel, user, atau sesi.
-- Jalankan pada project Supabase yang sama dengan SUPABASE_URL di EdgeOne.

GRANT USAGE ON SCHEMA public TO authenticated, service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- Conditional grants: patch tetap bisa dijalankan untuk mendiagnosis instalasi parsial.
DO $permissions$
BEGIN
  IF to_regclass('public.ledger_accounts') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT ON TABLE public.ledger_accounts TO authenticated';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.ledger_accounts TO service_role';
  END IF;
  IF to_regclass('public.debt_records') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT ON TABLE public.debt_records TO authenticated';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.debt_records TO service_role';
  END IF;
  IF to_regclass('public.debt_backups') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT ON TABLE public.debt_backups TO authenticated';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.debt_backups TO service_role';
  END IF;
  IF to_regclass('public.catatan_login_rate_limits') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.catatan_login_rate_limits TO service_role';
  END IF;

  IF to_regprocedure('public.create_debt_customer(jsonb)') IS NOT NULL THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_debt_customer(jsonb) TO authenticated'; END IF;
  IF to_regprocedure('public.update_debt_customer(jsonb,timestamptz)') IS NOT NULL THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.update_debt_customer(jsonb,timestamptz) TO authenticated'; END IF;
  IF to_regprocedure('public.add_debt_payment(uuid,bigint)') IS NOT NULL THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.add_debt_payment(uuid,bigint) TO authenticated'; END IF;
  IF to_regprocedure('public.delete_debt_customer(uuid)') IS NOT NULL THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_debt_customer(uuid) TO authenticated'; END IF;
  IF to_regprocedure('public.replace_debt_records(jsonb)') IS NOT NULL THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.replace_debt_records(jsonb) TO authenticated'; END IF;
  IF to_regprocedure('public.restore_debt_backup(uuid)') IS NOT NULL THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.restore_debt_backup(uuid) TO authenticated'; END IF;
  IF to_regprocedure('public.catatan_check_login_rate(text)') IS NOT NULL THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.catatan_check_login_rate(text) TO service_role'; END IF;
  IF to_regprocedure('public.catatan_clear_login_rate(text)') IS NOT NULL THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.catatan_clear_login_rate(text) TO service_role'; END IF;
END
$permissions$;

CREATE OR REPLACE FUNCTION public.catatan_health_check()
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, auth, pg_catalog
AS $$
  SELECT jsonb_build_object(
    'ledger_accounts_exists', to_regclass('public.ledger_accounts') IS NOT NULL,
    'debt_records_exists', to_regclass('public.debt_records') IS NOT NULL,
    'debt_backups_exists', to_regclass('public.debt_backups') IS NOT NULL,
    'login_rate_limits_exists', to_regclass('public.catatan_login_rate_limits') IS NOT NULL,
    'ledger_accounts_rls_enabled', COALESCE((SELECT relrowsecurity FROM pg_class WHERE oid=to_regclass('public.ledger_accounts')), false),
    'debt_records_rls_enabled', COALESCE((SELECT relrowsecurity FROM pg_class WHERE oid=to_regclass('public.debt_records')), false),
    'debt_backups_rls_enabled', COALESCE((SELECT relrowsecurity FROM pg_class WHERE oid=to_regclass('public.debt_backups')), false),
    'ledger_accounts_policy_exists', EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='ledger_accounts' AND policyname='ledger_accounts_read_own'),
    'debt_records_policy_exists', EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='debt_records' AND policyname='debt_records_read_own'),
    'debt_backups_policy_exists', EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='debt_backups' AND policyname='debt_backups_read_own'),
    'authenticated_can_read_accounts', CASE WHEN to_regclass('public.ledger_accounts') IS NULL THEN false ELSE has_table_privilege('authenticated', 'public.ledger_accounts', 'SELECT') END,
    'authenticated_can_read_debts', CASE WHEN to_regclass('public.debt_records') IS NULL THEN false ELSE has_table_privilege('authenticated', 'public.debt_records', 'SELECT') END,
    'authenticated_can_read_backups', CASE WHEN to_regclass('public.debt_backups') IS NULL THEN false ELSE has_table_privilege('authenticated', 'public.debt_backups', 'SELECT') END,
    'authenticated_can_execute_create', CASE WHEN to_regprocedure('public.create_debt_customer(jsonb)') IS NULL THEN false ELSE has_function_privilege('authenticated', 'public.create_debt_customer(jsonb)', 'EXECUTE') END,
    'authenticated_can_execute_update', CASE WHEN to_regprocedure('public.update_debt_customer(jsonb,timestamptz)') IS NULL THEN false ELSE has_function_privilege('authenticated', 'public.update_debt_customer(jsonb,timestamptz)', 'EXECUTE') END,
    'authenticated_can_execute_payment', CASE WHEN to_regprocedure('public.add_debt_payment(uuid,bigint)') IS NULL THEN false ELSE has_function_privilege('authenticated', 'public.add_debt_payment(uuid,bigint)', 'EXECUTE') END,
    'authenticated_can_execute_delete', CASE WHEN to_regprocedure('public.delete_debt_customer(uuid)') IS NULL THEN false ELSE has_function_privilege('authenticated', 'public.delete_debt_customer(uuid)', 'EXECUTE') END,
    'authenticated_can_execute_replace', CASE WHEN to_regprocedure('public.replace_debt_records(jsonb)') IS NULL THEN false ELSE has_function_privilege('authenticated', 'public.replace_debt_records(jsonb)', 'EXECUTE') END,
    'authenticated_can_execute_restore', CASE WHEN to_regprocedure('public.restore_debt_backup(uuid)') IS NULL THEN false ELSE has_function_privilege('authenticated', 'public.restore_debt_backup(uuid)', 'EXECUTE') END,
    'service_role_can_select_accounts', CASE WHEN to_regclass('public.ledger_accounts') IS NULL THEN false ELSE has_table_privilege('service_role', 'public.ledger_accounts', 'SELECT') END,
    'service_role_can_insert_accounts', CASE WHEN to_regclass('public.ledger_accounts') IS NULL THEN false ELSE has_table_privilege('service_role', 'public.ledger_accounts', 'INSERT') END,
    'service_role_can_execute_rate_check', CASE WHEN to_regprocedure('public.catatan_check_login_rate(text)') IS NULL THEN false ELSE has_function_privilege('service_role', 'public.catatan_check_login_rate(text)', 'EXECUTE') END,
    'service_role_can_execute_rate_clear', CASE WHEN to_regprocedure('public.catatan_clear_login_rate(text)') IS NULL THEN false ELSE has_function_privilege('service_role', 'public.catatan_clear_login_rate(text)', 'EXECUTE') END
  );
$$;

REVOKE ALL ON FUNCTION public.catatan_health_check() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.catatan_health_check() TO service_role;
