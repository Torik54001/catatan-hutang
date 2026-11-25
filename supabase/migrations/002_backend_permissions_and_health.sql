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
