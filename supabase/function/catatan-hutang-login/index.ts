import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function accountEmail(accountId: string) {
  // Email virtual internal untuk Supabase Auth; tidak digunakan untuk mengirim email.
  return `acct-${accountId}@catathutang-login.com`;
}

Deno.serve(async (request: Request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (request.method !== 'POST') return json(405, { error: 'Metode tidak didukung' });

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const secretKeyMap = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') ?? '{}');
    const publishableKeyMap = JSON.parse(Deno.env.get('SUPABASE_PUBLISHABLE_KEYS') ?? '{}');
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? secretKeyMap.default ?? Object.values(secretKeyMap)[0];
    const anonKey = request.headers.get('apikey') ?? Deno.env.get('SUPABASE_ANON_KEY') ?? publishableKeyMap.default ?? Object.values(publishableKeyMap)[0];
    const bootstrapAccountId = Deno.env.get('CATATAN_BOOTSTRAP_ACCOUNT_ID') ?? '';
    const bootstrapPin = Deno.env.get('CATATAN_BOOTSTRAP_PIN') ?? '';

    if (!supabaseUrl || !serviceKey || !anonKey) {
      return json(500, { error: 'Konfigurasi fungsi Supabase belum lengkap.' });
    }

    const body = await request.json().catch(() => ({}));
    const accountId = String(body.account_id ?? '').replace(/\D/g, '');
    const pin = String(body.pin ?? '');
    if (!/^\d{8,16}$/.test(accountId) || pin.length < 6 || pin.length > 72) {
      return json(400, { error: 'ID akun harus 8–16 angka dan PIN minimal 6 karakter.' });
    }
    if (!bootstrapAccountId || accountId !== bootstrapAccountId) {
      return json(401, { error: 'ID akun atau PIN salah.' });
    }

    const admin = createClient(supabaseUrl, serviceKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    // Batasi percobaan login bersama lintas perangkat dan lintas instance function.
    const { data: allowed, error: rateError } = await admin.rpc('catatan_check_login_rate', {
      p_account_code: accountId,
    });
    if (rateError) {
      console.error('Rate limit check failed:', rateError.message);
      return json(503, { error: 'Pemeriksaan keamanan belum siap. Jalankan SQL setup terlebih dahulu.' });
    }
    if (allowed !== true) return json(429, { error: 'Terlalu banyak percobaan. Coba kembali setelah 15 menit.' });

    const { data: account, error: accountError } = await admin
      .from('ledger_accounts')
      .select('id, auth_user_id')
      .eq('account_code', accountId)
      .maybeSingle();

    if (accountError) {
      console.error('Account lookup failed:', accountError.message);
      return json(503, { error: 'Database belum siap. Pastikan SQL setup sudah dijalankan.' });
    }

    const email = accountEmail(accountId);
    if (!account) {
      // Akun pusat hanya dapat dibuat sekali dan hanya dengan ID/PIN bootstrap dari Secrets.
      if (bootstrapAccountId !== accountId || bootstrapPin.length < 6 || bootstrapPin !== pin) {
        return json(401, { error: 'ID akun atau PIN salah, atau akun belum diinisialisasi.' });
      }

      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email,
        password: pin,
        email_confirm: true,
        user_metadata: { account_code: accountId, app: 'CatatHutang' },
      });
      if (createError || !created.user) {
        console.error('Bootstrap auth user failed:', createError?.message);
        return json(409, { error: 'Pembuatan akun pusat belum berhasil. Coba login sekali lagi.' });
      }

      const { error: insertAccountError } = await admin.from('ledger_accounts').insert({
        account_code: accountId,
        auth_user_id: created.user.id,
      });
      if (insertAccountError) {
        console.error('Bootstrap account mapping failed:', insertAccountError.message);
        await admin.auth.admin.deleteUser(created.user.id);
        return json(500, { error: 'Akun login dibuat tetapi pemetaan database gagal. Periksa SQL lalu ulangi.' });
      }
    }

    const { data: signedIn, error: signInError } = await authClient.auth.signInWithPassword({
      email,
      password: pin,
    });
    if (signInError || !signedIn.session) {
      return json(401, { error: 'ID akun atau PIN salah.' });
    }

    await admin.rpc('catatan_clear_login_rate', { p_account_code: accountId });
    return json(200, {
      session: {
        access_token: signedIn.session.access_token,
        refresh_token: signedIn.session.refresh_token,
      },
    });
  } catch (error) {
    console.error('Login function error:', error);
    return json(500, { error: 'Login gagal diproses. Periksa konfigurasi server.' });
  }
});
