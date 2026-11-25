// EdgeOne Pages Function: POST /api/login
// Supabase Secret Key is only read server-side from context.env and never returned.
const jsonHeaders = (origin = '*') => ({
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store, max-age=0',
  'Access-Control-Allow-Origin': origin,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
  'Vary': 'Origin',
});
const json = (status, body, origin) => new Response(JSON.stringify(body), { status, headers: jsonHeaders(origin) });
const value = (env, name) => String(env?.[name] ?? '').trim();
const accountEmail = (accountId) => `acct-${accountId}@catathutang-login.com`;

function keyFromMap(raw) {
  if (!raw) return '';
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return String(parsed.default || Object.values(parsed)[0] || '').trim();
  } catch {}
  return '';
}

async function callSupabase(baseUrl, path, apiKey, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('apikey', apiKey);
  if (options.body !== undefined && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  // Legacy JWT keys need Authorization to select the service_role/anon role.
  // New sb_secret_/sb_publishable_ keys are API keys, not JWTs; keep them in apikey.
  if (apiKey.startsWith('eyJ') && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${apiKey}`);
  const response = await fetch(`${baseUrl}${path}`, { ...options, headers });
  let data = null;
  const text = await response.text();
  if (text) {
    try { data = JSON.parse(text); }
    catch { data = { message: text.slice(0, 500) }; }
  }
  return { response, data };
}

export async function onRequest(context) {
  const request = context.request;
  const origin = request.headers.get('Origin') || '*';
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: jsonHeaders(origin) });
  if (request.method !== 'POST') return json(405, { error: 'Metode tidak didukung. Gunakan POST untuk login.' }, origin);

  try {
    const env = context.env || {};
    const supabaseUrl = value(env, 'SUPABASE_URL').replace(/\/$/, '');
    const publicKey = value(env, 'SUPABASE_PUBLISHABLE_KEY')
      || value(env, 'SUPABASE_ANON_KEY')
      || keyFromMap(value(env, 'SUPABASE_PUBLISHABLE_KEYS'));
    const secretKey = value(env, 'SUPABASE_SECRET_KEY')
      || value(env, 'SUPABASE_SERVICE_ROLE_KEY')
      || keyFromMap(value(env, 'SUPABASE_SECRET_KEYS'));
    const bootstrapAccountId = value(env, 'CATATAN_BOOTSTRAP_ACCOUNT_ID').replace(/\D/g, '');
    const bootstrapPin = value(env, 'CATATAN_BOOTSTRAP_PIN');

    if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(supabaseUrl)) {
      return json(503, { error: 'Environment SUPABASE_URL belum benar.' }, origin);
    }
    if (!/^(sb_publishable_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)$/.test(publicKey)) {
      return json(503, { error: 'Publishable Key belum diisi. Isi SUPABASE_PUBLISHABLE_KEY atau SUPABASE_ANON_KEY.' }, origin);
    }
    if (!/^(sb_secret_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)$/.test(secretKey)) {
      return json(503, { error: 'Secret Key backend belum diisi. Isi SUPABASE_SECRET_KEY atau SUPABASE_SERVICE_ROLE_KEY.' }, origin);
    }

    const contentLength = Number(request.headers.get('Content-Length') || 0);
    if (contentLength > 8192) return json(413, { error: 'Permintaan terlalu besar.' }, origin);
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object') return json(400, { error: 'Format permintaan login tidak valid.' }, origin);
    const accountId = String(body.account_id ?? '').replace(/\D/g, '');
    const pin = String(body.pin ?? '');
    if (!/^\d{8,16}$/.test(accountId) || pin.length < 6 || pin.length > 72) {
      return json(400, { error: 'ID akun harus 8–16 angka dan PIN minimal 6 karakter.' }, origin);
    }

    // Database-backed rate limit; this is shared by all devices and EdgeOne instances.
    const rate = await callSupabase(supabaseUrl, '/rest/v1/rpc/catatan_check_login_rate', secretKey, {
      method: 'POST', body: JSON.stringify({ p_account_code: accountId }),
    });
    if (!rate.response.ok) {
      console.error('Login rate-limit RPC failed:', rate.response.status, rate.data?.message || rate.data?.error || '');
      return json(503, { error: 'Pemeriksaan keamanan belum siap. Pastikan SQL migration Catat Hutang sudah dijalankan di Supabase.' }, origin);
    }
    if (rate.data !== true) return json(429, { error: 'Terlalu banyak percobaan login. Coba kembali setelah 15 menit.' }, origin);

    const accountQuery = `/rest/v1/ledger_accounts?select=id,auth_user_id&account_code=eq.${encodeURIComponent(accountId)}&limit=1`;
    const lookup = await callSupabase(supabaseUrl, accountQuery, secretKey, { method: 'GET' });
    if (!lookup.response.ok || !Array.isArray(lookup.data)) {
      console.error('Account lookup failed:', lookup.response.status, lookup.data?.message || lookup.data?.error || '');
      return json(503, { error: 'Database akun belum siap. Periksa SQL migration dan tabel ledger_accounts.' }, origin);
    }

    let account = lookup.data[0] || null;
    if (!account) {
      // Bootstrap is allowed only for this account ID and this PIN, exactly as stored in EdgeOne.
      if (!/^\d{8,16}$/.test(bootstrapAccountId) || accountId !== bootstrapAccountId || bootstrapPin.length < 6 || pin !== bootstrapPin) {
        return json(401, { error: 'ID akun atau PIN salah.' }, origin);
      }

      const createUser = await callSupabase(supabaseUrl, '/auth/v1/admin/users', secretKey, {
        method: 'POST',
        body: JSON.stringify({
          email: accountEmail(accountId),
          password: pin,
          email_confirm: true,
          user_metadata: { account_code: accountId, app: 'CatatHutang' },
        }),
      });
      if (!createUser.response.ok) {
        console.error('Bootstrap user creation failed:', createUser.response.status, createUser.data?.message || createUser.data?.msg || '');
        return json(409, { error: 'Pembuatan akun pusat gagal. Periksa Auth Supabase dan Secret Key EdgeOne, lalu coba kembali.' }, origin);
      }
      const user = createUser.data?.user || createUser.data;
      const userId = String(user?.id || '');
      if (!userId) return json(500, { error: 'Supabase tidak mengembalikan ID pengguna untuk akun pusat.' }, origin);

      const insertAccount = await callSupabase(supabaseUrl, '/rest/v1/ledger_accounts', secretKey, {
        method: 'POST',
        headers: { Prefer: 'return=representation' },
        body: JSON.stringify({ account_code: accountId, auth_user_id: userId }),
      });
      if (!insertAccount.response.ok) {
        console.error('Bootstrap account mapping failed:', insertAccount.response.status, insertAccount.data?.message || insertAccount.data?.details || '');
        await callSupabase(supabaseUrl, `/auth/v1/admin/users/${encodeURIComponent(userId)}`, secretKey, { method: 'DELETE' }).catch(() => null);
        return json(500, { error: 'Akun Auth berhasil dibuat tetapi pemetaan database gagal. Periksa SQL migration lalu ulangi login.' }, origin);
      }
      account = { auth_user_id: userId };
    }

    if (!account?.auth_user_id) return json(503, { error: 'Pemetaan akun pusat tidak lengkap di database.' }, origin);

    // Sign in with the public key. Only the user's session tokens leave this function.
    const signIn = await callSupabase(supabaseUrl, '/auth/v1/token?grant_type=password', publicKey, {
      method: 'POST',
      body: JSON.stringify({ email: accountEmail(accountId), password: pin }),
    });
    if (!signIn.response.ok || !signIn.data?.access_token || !signIn.data?.refresh_token) {
      return json(401, { error: 'ID akun atau PIN salah.' }, origin);
    }

    await callSupabase(supabaseUrl, '/rest/v1/rpc/catatan_clear_login_rate', secretKey, {
      method: 'POST', body: JSON.stringify({ p_account_code: accountId }),
    }).catch((error) => console.error('Login rate clear failed:', error));

    return json(200, {
      session: {
        access_token: signIn.data.access_token,
        refresh_token: signIn.data.refresh_token,
      },
    }, origin);
  } catch (error) {
    console.error('EdgeOne login handler failed:', error?.message || error);
    return json(500, { error: 'Login gagal diproses oleh server EdgeOne. Periksa konfigurasi Environment dan log Function.' }, origin);
  }
}
