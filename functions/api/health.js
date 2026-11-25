// EdgeOne Pages Function: GET /api/health
// Active checks: EdgeOne env, Supabase Auth, DB objects, grants and login RPC.
// Never returns API keys, PIN, database rows, or raw Supabase error text.
const headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store, max-age=0',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS, HEAD',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
};
const value = (env, name) => String(env?.[name] ?? '').trim();
function keyFromEnv(env, directName, mapName, legacyName) {
  const direct = value(env, directName) || value(env, legacyName);
  if (direct) return direct;
  const raw = env?.[mapName];
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return String(raw.default || Object.values(raw)[0] || '').trim();
  if (typeof raw === 'string' && raw.trim()) {
    try { const obj = JSON.parse(raw); if (obj && typeof obj === 'object' && !Array.isArray(obj)) return String(obj.default || Object.values(obj)[0] || '').trim(); }
    catch {}
  }
  return '';
}
async function requestJson(url, key, method = 'GET', body) {
  const h = new Headers({ apikey: key, Accept: 'application/json' });
  if (key.startsWith('eyJ')) h.set('Authorization', `Bearer ${key}`);
  if (body !== undefined) h.set('Content-Type', 'application/json');
  const response = await fetch(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store' });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  return { ok: response.ok, status: response.status, data };
}
const result = (status, body) => new Response(JSON.stringify(body), { status, headers });

export async function onRequest(context) {
  const method = context.request.method;
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers });
  if (method === 'HEAD') return new Response(null, { status: 204, headers });
  if (method !== 'GET') return result(405, { error: 'Gunakan GET.' });

  const env = context.env || {};
  const url = value(env, 'SUPABASE_URL').replace(/\/+$/, '');
  const publicKey = keyFromEnv(env, 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_PUBLISHABLE_KEYS', 'SUPABASE_ANON_KEY');
  const secretKey = keyFromEnv(env, 'SUPABASE_SECRET_KEY', 'SUPABASE_SECRET_KEYS', 'SUPABASE_SERVICE_ROLE_KEY');
  const accountId = value(env, 'CATATAN_BOOTSTRAP_ACCOUNT_ID').replace(/\D/g, '');
  const pin = value(env, 'CATATAN_BOOTSTRAP_PIN');

  const envChecks = {
    supabaseUrl: /^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(url),
    publishableKey: /^(sb_publishable_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)$/.test(publicKey),
    secretKey: /^(sb_secret_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)$/.test(secretKey),
    bootstrapAccountId: /^\d{8,16}$/.test(accountId),
    bootstrapPin: pin.length >= 6,
  };
  const missing = Object.entries(envChecks).filter(([, ok]) => !ok).map(([name]) => name);
  if (missing.length) return result(503, {
    ok: false, service: 'catat-hutang-edgeone-api', checks: envChecks, missing,
    diagnostics: { authApi: 'skipped', database: 'skipped' },
    note: 'Nama dan status variabel diperiksa; nilainya tidak ditampilkan.',
  });

  let authApi = { ok: false, status: 0 };
  let database = { ok: false, status: 0, schema: null };
  try { authApi = await requestJson(`${url}/auth/v1/health`, publicKey); }
  catch { authApi = { ok: false, status: 0 }; }
  try {
    const db = await requestJson(`${url}/rest/v1/rpc/catatan_health_check`, secretKey, 'POST', {});
    database = { ok: db.ok && !!db.data && Object.values(db.data).every(v => v === true), status: db.status, schema: db.ok ? db.data : null };
  } catch { database = { ok: false, status: 0, schema: null }; }

  const ok = authApi.ok && database.ok;
  return result(ok ? 200 : 503, {
    ok, service: 'catat-hutang-edgeone-api', checks: envChecks, missing: [],
    diagnostics: {
      authApi: authApi.ok ? 'connected' : (authApi.status ? `failed_http_${authApi.status}` : 'unreachable'),
      database: database.ok ? 'ready' : (database.status === 404 ? 'migration_002_missing' : database.status === 401 || database.status === 403 ? 'secret_key_rejected' : database.status === 200 ? 'schema_or_permissions_incomplete' : database.status ? `failed_http_${database.status}` : 'unreachable'),
      schema: database.schema,
    },
    note: 'Pemeriksaan aktif Auth, tabel, hak akses service_role, dan RPC. Tidak ada nilai key atau PIN yang ditampilkan.',
  });
}
