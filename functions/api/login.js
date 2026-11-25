// EdgeOne Pages Function: POST /api/login
// Rahasia Supabase hanya dibaca di server dari context.env.
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

function keyFromEnv(env, directName, mapName) {
  const direct = value(env, directName);
  if (direct) return direct;
  const raw = env?.[mapName];
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return String(raw.default || Object.values(raw)[0] || '').trim();
  }
  if (typeof raw === 'string' && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return String(parsed.default || Object.values(parsed)[0] || '').trim();
      }
    } catch {}
  }
  return '';
}

function normalizeError(data) {
  return {
    code: String(data?.code || data?.error_code || '').slice(0, 80),
    message: String(data?.message || data?.msg || data?.error_description || data?.error || '').slice(0, 300),
  };
}

async function findAuthUserByEmail(baseUrl, secretKey, email) {
  // Repairs an interrupted first login without creating a duplicate Auth user.
  // The PIN is still checked later by the normal password-token endpoint.
  for (let page = 1; page <= 10; page += 1) {
    const listed = await callSupabase(baseUrl, `/auth/v1/admin/users?page=${page}&per_page=1000`, secretKey, { method: 'GET' });
    if (!listed.response.ok) return { error: listed };
    const users = Array.isArray(listed.data) ? listed.data : listed.data?.users;
    if (!Array.isArray(users)) return { error: listed };
    const found = users.find((user) => String(user?.email || '').toLowerCase() === email.toLowerCase());
    if (found?.id) return { user: found };
    if (users.length < 1000) break;
  }
  return { user: null };
}

async function callSupabase(baseUrl, path, apiKey, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('apikey', apiKey);
  if (options.body !== undefined && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  // Key JWT lama memerlukan Authorization. sb_secret_/sb_publishable_ bukan JWT.
  if (apiKey.startsWith('eyJ') && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${apiKey}`);
  const response = await fetch(`${baseUrl}${path}`, { ...options, headers, cache: 'no-store' });
  const rawText = await response.text();
  let data = null;
  if (rawText) {
    try { data = JSON.parse(rawText); }
    catch { data = { message: rawText.slice(0, 300) }; }
  }
  return { response, data, error: normalizeError(data) };
}

function databaseFailure(stage, result) {
  const status = result?.response?.status || 0;
  const code = result?.error?.code || '';
  console.error(`Catat Hutang ${stage} failed:`, status, code, result?.error?.message || '');
  if (code === '42501' || /permission denied/i.test(result?.error?.message || '')) {
    return json(503, { error: 'Izin tabel Supabase belum lengkap. Jalankan SQL migration 002 untuk memperbaiki hak akses server.', stage, code: code || '42501' }, '*');
  }
  if (status === 401 || status === 403) {
    return json(503, { error: 'Supabase menolak Secret Key server. Periksa SUPABASE_SECRET_KEY atau SUPABASE_SERVICE_ROLE_KEY dan pastikan berasal dari project yang sama.', stage, code: code || `HTTP_${status}` }, '*');
  }
  if (status === 404 || code === 'PGRST202' || code === 'PGRST205') {
    return json(503, { error: 'Struktur database Catat Hutang belum lengkap. Jalankan SQL migration 001 dan 002 pada project Supabase yang sama.', stage, code: code || `HTTP_${status}` }, '*');
  }
  return json(503, { error: 'Supabase gagal memproses permintaan server. Periksa koneksi, URL project, dan log Function.', stage, code: code || (status ? `HTTP_${status}` : 'NETWORK_ERROR') }, '*');
}

export async function onRequest(context) {
  const request = context.request;
  const origin = request.headers.get('Origin') || '*';
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: jsonHeaders(origin) });
  if (request.method !== 'POST') return json(405, { error: 'Metode tidak didukung. Gunakan POST untuk login.' }, origin);

  try {
    const env = context.env || {};
    const supabaseUrl = value(env, 'SUPABASE_URL').replace(/\/+$/, '');
    const publicKey = keyFromEnv(env, 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_PUBLISHABLE_KEYS') || value(env, 'SUPABASE_ANON_KEY');
    const secretKey = keyFromEnv(env, 'SUPABASE_SECRET_KEY', 'SUPABASE_SECRET_KEYS') || value(env, 'SUPABASE_SERVICE_ROLE_KEY');
    const bootstrapAccountId = value(env, 'CATATAN_BOOTSTRAP_ACCOUNT_ID').replace(/\D/g, '');
    const bootstrapPin = value(env, 'CATATAN_BOOTSTRAP_PIN');

    if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(supabaseUrl)) {
      return json(503, { error: 'Environment SUPABASE_URL belum benar atau bukan URL project Supabase.' }, origin);
    }
    if (!/^(sb_publishable_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)$/.test(publicKey)) {
      return json(503, { error: 'Publishable Key belum benar. Isi SUPABASE_PUBLISHABLE_KEY atau SUPABASE_ANON_KEY dari project yang sama.' }, origin);
    }
    if (!/^(sb_secret_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)$/.test(secretKey)) {
      return json(503, { error: 'Secret Key backend belum benar. Isi SUPABASE_SECRET_KEY atau SUPABASE_SERVICE_ROLE_KEY di Environment Production.' }, origin);
    }

    const rawBody = await request.text();
    if (rawBody.length > 8192) return json(413, { error: 'Permintaan terlalu besar.' }, origin);
    let body;
    try { body = JSON.parse(rawBody || '{}'); }
    catch { return json(400, { error: 'Format permintaan login bukan JSON yang valid.' }, origin); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return json(400, { error: 'Format permintaan login tidak valid.' }, origin);

    const accountId = String(body.account_id ?? '').replace(/\D/g, '');
    const pin = String(body.pin ?? '');
    if (!/^\d{8,16}$/.test(accountId) || pin.length < 6 || pin.length > 72 || /[\u0000-\u001f\u007f]/.test(pin)) {
      return json(400, { error: 'ID akun harus 8–16 angka dan PIN harus 6–72 karakter.' }, origin);
    }

    const rate = await callSupabase(supabaseUrl, '/rest/v1/rpc/catatan_check_login_rate', secretKey, {
      method: 'POST', body: JSON.stringify({ p_account_code: accountId }),
    });
    if (!rate.response.ok) return databaseFailure('rate_limit', rate);
    if (rate.data === false) return json(429, { error: 'Terlalu banyak percobaan login. Coba kembali setelah 15 menit.' }, origin);
    if (rate.data !== true) return json(503, { error: 'RPC pembatasan login memberi hasil yang tidak dikenali. Jalankan SQL migration 001 dan 002.' , stage: 'rate_limit' }, origin);

    const accountQuery = `/rest/v1/ledger_accounts?select=id,auth_user_id&account_code=eq.${encodeURIComponent(accountId)}&limit=1`;
    const lookup = await callSupabase(supabaseUrl, accountQuery, secretKey, { method: 'GET' });
    if (!lookup.response.ok || !Array.isArray(lookup.data)) return databaseFailure('account_lookup', lookup);

    let account = lookup.data[0] || null;
    if (!account) {
      if (!/^\d{8,16}$/.test(bootstrapAccountId) || accountId !== bootstrapAccountId || bootstrapPin.length < 6 || pin !== bootstrapPin) {
        return json(401, { error: 'ID akun atau PIN salah.' }, origin);
      }

      const email = accountEmail(accountId);
      const existingAuth = await findAuthUserByEmail(supabaseUrl, secretKey, email);
      if (existingAuth.error) return databaseFailure('bootstrap_user_lookup', existingAuth.error);

      let user = existingAuth.user;
      let createdUserNow = false;
      if (!user) {
        const createUser = await callSupabase(supabaseUrl, '/auth/v1/admin/users', secretKey, {
          method: 'POST',
          body: JSON.stringify({
            email, password: pin, email_confirm: true,
            user_metadata: { account_code: accountId, app: 'CatatHutang' },
          }),
        });
        if (!createUser.response.ok) {
          console.error('Bootstrap Auth user creation failed:', createUser.response.status, createUser.error.code, createUser.error.message);
          const duplicate = /already|exists|registered|duplicate/i.test(createUser.error.message) || createUser.error.code === 'email_exists';
          return json(duplicate ? 409 : 503, {
            error: duplicate
              ? 'Akun Auth untuk ID ini sudah ada tetapi belum ditemukan pada daftar Auth. Periksa Authentication > Users dan log Function.'
              : 'Pembuatan akun pusat gagal. Periksa Secret Key, Auth Supabase, dan log Function.',
            stage: 'bootstrap_create_user', code: createUser.error.code || `HTTP_${createUser.response.status}`,
          }, origin);
        }
        user = createUser.data?.user || createUser.data;
        createdUserNow = true;
      }
      const userId = String(user?.id || '');
      if (!userId) return json(503, { error: 'Supabase berhasil merespons tetapi tidak mengembalikan ID pengguna.' , stage: 'bootstrap_create_user' }, origin);

      const insertAccount = await callSupabase(supabaseUrl, '/rest/v1/ledger_accounts', secretKey, {
        method: 'POST', headers: { Prefer: 'return=representation' },
        body: JSON.stringify({ account_code: accountId, auth_user_id: userId }),
      });
      if (!insertAccount.response.ok) {
        console.error('Bootstrap account mapping failed:', insertAccount.response.status, insertAccount.error.code, insertAccount.error.message);
        if (createdUserNow) {
          await callSupabase(supabaseUrl, `/auth/v1/admin/users/${encodeURIComponent(userId)}`, secretKey, { method: 'DELETE' }).catch(() => null);
        }
        return databaseFailure('bootstrap_mapping', insertAccount);
      }
      account = { auth_user_id: userId };
    }

    if (!account?.auth_user_id) return json(503, { error: 'Data pemetaan akun tidak lengkap. Periksa ledger_accounts.' , stage: 'account_lookup' }, origin);

    const signIn = await callSupabase(supabaseUrl, '/auth/v1/token?grant_type=password', publicKey, {
      method: 'POST', body: JSON.stringify({ email: accountEmail(accountId), password: pin }),
    });
    if (!signIn.response.ok || !signIn.data?.access_token || !signIn.data?.refresh_token) {
      if (signIn.response.status === 429) return json(429, { error: 'Supabase Auth membatasi percobaan masuk. Tunggu beberapa menit lalu coba lagi.' }, origin);
      if (signIn.response.status >= 500) {
        console.error('Supabase Auth sign-in failed:', signIn.response.status, signIn.error.code, signIn.error.message);
        return json(503, { error: 'Layanan autentikasi Supabase sedang gagal. Periksa Auth API dan project URL.' , stage: 'auth_sign_in', code: signIn.error.code || `HTTP_${signIn.response.status}` }, origin);
      }
      return json(401, { error: 'ID akun atau PIN salah.' }, origin);
    }
    const signedInUserId = String(signIn.data?.user?.id || '');
    if (!signedInUserId || signedInUserId !== String(account.auth_user_id)) {
      console.error('Account/Auth mapping mismatch for account code:', accountId);
      return json(409, { error: 'Pemetaan akun pusat tidak cocok dengan pengguna Supabase Auth. Jangan hapus akun atau data; periksa pasangan account_code dan auth_user_id di ledger_accounts.', stage: 'account_mapping' }, origin);
    }

    await callSupabase(supabaseUrl, '/rest/v1/rpc/catatan_clear_login_rate', secretKey, {
      method: 'POST', body: JSON.stringify({ p_account_code: accountId }),
    }).catch((error) => console.error('Login rate clear failed:', error?.message || error));

    return json(200, { session: { access_token: signIn.data.access_token, refresh_token: signIn.data.refresh_token } }, origin);
  } catch (error) {
    console.error('EdgeOne login handler failed:', error?.message || error);
    return json(500, { error: 'Login gagal diproses oleh server EdgeOne. Periksa log Function untuk detail tahap kegagalan.' }, request.headers.get('Origin') || '*');
  }
}
