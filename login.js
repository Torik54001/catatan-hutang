/**
 * Catat Hutang Cloud — centralized login API on EdgeOne Pages Functions.
 * Route: POST /api/login
 * SUPABASE_SECRET_KEY is used for PostgREST/RPC with apikey only.
 * SUPABASE_SERVICE_ROLE_KEY (legacy JWT) is needed only for first-time Auth user
 * creation; it can be removed after the account mapping has been created.
 * Never return or log any key, the bootstrap PIN, or incoming credentials.
 */
function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, max-age=0',
      'Pragma': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function accountEmail(accountId) {
  return `acct-${accountId}@catathutang-login.com`;
}

function secretHeaders(secretKey, extra = {}) {
  // New sb_secret_ keys are opaque API keys, not JWTs: send apikey only.
  return { apikey: secretKey, ...extra };
}

function legacyAdminHeaders(serviceRoleKey, extra = {}) {
  // Legacy service_role is a JWT and is used only for Auth Admin bootstrap.
  return { apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}`, ...extra };
}

async function readJson(response) {
  const raw = await response.text();
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return { message: raw.slice(0, 300) }; }
}

async function supabaseSecretFetch(baseUrl, secretKey, path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: secretHeaders(secretKey, options.headers || {}),
  });
  const body = await readJson(response);
  return { response, body };
}

async function supabaseAuthAdminFetch(baseUrl, serviceRoleKey, path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: legacyAdminHeaders(serviceRoleKey, options.headers || {}),
  });
  const body = await readJson(response);
  return { response, body };
}

async function rpc(baseUrl, secretKey, name, payload) {
  return supabaseSecretFetch(baseUrl, secretKey, `/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function onRequestPost({ request, env }) {
  const supabaseUrl = String(env?.SUPABASE_URL || '').trim().replace(/\/$/, '');
  const publishableKey = String(env?.SUPABASE_PUBLISHABLE_KEY || '').trim();
  const secretKey = String(env?.SUPABASE_SECRET_KEY || '').trim();
  const serviceRoleKey = String(env?.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  const bootstrapAccountId = String(env?.CATATAN_BOOTSTRAP_ACCOUNT_ID || '').replace(/\D/g, '');

  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(supabaseUrl)
      || !publishableKey.startsWith('sb_publishable_') || !secretKey.startsWith('sb_secret_')
      || !/^\d{8,16}$/.test(bootstrapAccountId)) {
    return json(503, {
      error: 'Environment EdgeOne belum lengkap. Periksa SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SUPABASE_SECRET_KEY, dan CATATAN_BOOTSTRAP_ACCOUNT_ID.',
    });
  }

  let input;
  try { input = await request.json(); }
  catch { return json(400, { error: 'Format permintaan login tidak valid.' }); }

  const accountId = String(input?.account_id || '').replace(/\D/g, '');
  const pin = String(input?.pin || '');
  if (!/^\d{8,16}$/.test(accountId) || pin.length < 6 || pin.length > 72) {
    return json(400, { error: 'ID akun harus 8–16 angka dan PIN minimal 6 karakter.' });
  }
  if (accountId !== bootstrapAccountId) {
    return json(401, { error: 'ID akun atau PIN salah.' });
  }

  try {
    // Shared server-side rate limiting across EdgeOne instances and devices.
    const rate = await rpc(supabaseUrl, secretKey, 'catatan_check_login_rate', {
      p_account_code: accountId,
    });
    if (!rate.response.ok) {
      console.error('CatatHutang rate-limit RPC failed:', rate.response.status);
      return json(503, { error: 'Pemeriksaan keamanan belum siap. Pastikan SQL database sudah dijalankan.' });
    }
    if (rate.body !== true) {
      return json(429, { error: 'Terlalu banyak percobaan. Coba kembali setelah 15 menit.' });
    }

    const lookup = new URLSearchParams({
      select: 'id,auth_user_id',
      account_code: `eq.${accountId}`,
      limit: '1',
    });
    const accountResult = await supabaseSecretFetch(
      supabaseUrl, secretKey, `/rest/v1/ledger_accounts?${lookup.toString()}`, { method: 'GET' },
    );
    if (!accountResult.response.ok || !Array.isArray(accountResult.body)) {
      console.error('CatatHutang account lookup failed:', accountResult.response.status);
      return json(503, { error: 'Database belum siap. Pastikan SQL setup sudah dijalankan pada proyek Supabase yang benar.' });
    }

    const email = accountEmail(accountId);
    if (accountResult.body.length === 0) {
      // The bootstrap PIN is accepted only to create the first account mapping.
      const bootstrapPin = String(env?.CATATAN_BOOTSTRAP_PIN || '');
      if (bootstrapPin.length < 6) {
        return json(503, { error: 'Akun pusat belum dibuat. Isi CATATAN_BOOTSTRAP_PIN di Environment EdgeOne untuk proses pertama.' });
      }
      if (pin !== bootstrapPin) return json(401, { error: 'ID akun atau PIN salah.' });
      if (!serviceRoleKey) {
        return json(503, { error: 'Akun pusat belum dibuat. Tambahkan SUPABASE_SERVICE_ROLE_KEY sementara untuk proses bootstrap pertama.' });
      }

      const created = await supabaseAuthAdminFetch(supabaseUrl, serviceRoleKey, '/auth/v1/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password: pin,
          email_confirm: true,
          user_metadata: { account_code: accountId, app: 'CatatHutang' },
        }),
      });
      const userId = created.body?.id || created.body?.user?.id;
      if (!created.response.ok || !userId) {
        console.error('CatatHutang bootstrap user creation failed:', created.response.status);
        return json(409, { error: 'Pembuatan akun pusat belum berhasil. Periksa key server sementara dan coba lagi.' });
      }

      const inserted = await supabaseSecretFetch(supabaseUrl, secretKey, '/rest/v1/ledger_accounts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
        body: JSON.stringify({ account_code: accountId, auth_user_id: userId }),
      });
      if (!inserted.response.ok) {
        console.error('CatatHutang bootstrap account mapping failed:', inserted.response.status);
        await supabaseAuthAdminFetch(supabaseUrl, serviceRoleKey, `/auth/v1/admin/users/${encodeURIComponent(userId)}`, { method: 'DELETE' });
        return json(500, { error: 'Akun login terbentuk tetapi penyimpanan akun pusat gagal. Periksa SQL lalu ulangi.' });
      }
    }

    // Sign in using the public key; the resulting user JWT is used by the browser
    // for RLS-protected records and Supabase Realtime.
    const signedInResponse = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        apikey: publishableKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password: pin }),
    });
    const signedIn = await readJson(signedInResponse);
    if (!signedInResponse.ok || !signedIn?.access_token || !signedIn?.refresh_token) {
      return json(401, { error: 'ID akun atau PIN salah.' });
    }

    await rpc(supabaseUrl, secretKey, 'catatan_clear_login_rate', {
      p_account_code: accountId,
    });

    return json(200, {
      session: {
        access_token: signedIn.access_token,
        refresh_token: signedIn.refresh_token,
      },
    });
  } catch (error) {
    // Do not log request payloads, passwords, or any environment values.
    console.error('CatatHutang EdgeOne login error:', error?.message || 'unknown');
    return json(500, { error: 'Login gagal diproses oleh server EdgeOne. Periksa Environment Variables dan koneksi database.' });
  }
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: { Allow: 'POST, OPTIONS' } });
}

export async function onRequest({ request, env }) {
  if (request.method === 'POST') return onRequestPost({ request, env });
  if (request.method === 'OPTIONS') return onRequestOptions();
  return json(405, { error: 'Metode tidak didukung. Gunakan POST untuk login.' });
}
