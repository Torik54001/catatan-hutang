// EdgeOne Pages Function: GET /api/health
// Safe diagnostics: reports presence/type only, never returns any secret value.
const headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store, max-age=0',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS, HEAD',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
};
const value = (env, name) => String(env?.[name] ?? '').trim();

export async function onRequest(context) {
  const method = context.request.method;
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers });
  if (method === 'HEAD') return new Response(null, { status: 204, headers });
  if (method !== 'GET') return new Response(JSON.stringify({ error: 'Gunakan GET.' }), { status: 405, headers });
  const env = context.env || {};
  const url = value(env, 'SUPABASE_URL');
  const publicKey = value(env, 'SUPABASE_PUBLISHABLE_KEY') || value(env, 'SUPABASE_ANON_KEY') || value(env, 'SUPABASE_PUBLISHABLE_KEYS');
  const secretKey = value(env, 'SUPABASE_SECRET_KEY') || value(env, 'SUPABASE_SERVICE_ROLE_KEY') || value(env, 'SUPABASE_SECRET_KEYS');
  const accountId = value(env, 'CATATAN_BOOTSTRAP_ACCOUNT_ID').replace(/\D/g, '');
  const pin = value(env, 'CATATAN_BOOTSTRAP_PIN');
  const checks = {
    supabaseUrl: /^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(url),
    publishableKey: /^(sb_publishable_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+|\{)/.test(publicKey),
    secretKey: /^(sb_secret_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+|\{)/.test(secretKey),
    bootstrapAccountId: /^\d{8,16}$/.test(accountId),
    bootstrapPin: pin.length >= 6,
  };
  const missing = Object.entries(checks).filter(([, ok]) => !ok).map(([name]) => name);
  return new Response(JSON.stringify({
    ok: missing.length === 0,
    service: 'catat-hutang-edgeone-api',
    checks,
    missing,
    note: 'Tidak ada nilai Environment atau Secret yang ditampilkan.',
  }), { status: missing.length ? 503 : 200, headers });
}
