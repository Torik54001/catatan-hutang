// EdgeOne Pages Function: GET /api/runtime-config
// Only project URL and Publishable Key are exposed to the browser.
const headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store, max-age=0',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS, HEAD',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
};
const value = (env, name) => String(env?.[name] ?? '').trim();
function keyFromEnv(env) {
  const direct = value(env, 'SUPABASE_PUBLISHABLE_KEY') || value(env, 'SUPABASE_ANON_KEY');
  if (direct) return direct;
  const raw = env?.SUPABASE_PUBLISHABLE_KEYS;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return String(raw.default || Object.values(raw)[0] || '').trim();
  if (typeof raw === 'string' && raw.trim()) {
    try { const obj = JSON.parse(raw); if (obj && typeof obj === 'object' && !Array.isArray(obj)) return String(obj.default || Object.values(obj)[0] || '').trim(); }
    catch {}
  }
  return '';
}
export async function onRequest(context) {
  const request = context.request;
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });
  if (request.method === 'HEAD') return new Response(null, { status: 204, headers });
  if (request.method !== 'GET') return new Response(JSON.stringify({ error: 'Metode tidak didukung. Gunakan GET.' }), { status: 405, headers: { ...headers, Allow: 'GET, HEAD, OPTIONS' } });

  const env = context.env || {};
  const supabaseUrl = value(env, 'SUPABASE_URL').replace(/\/+$/, '');
  const publishableKey = keyFromEnv(env);
  const defaultAccountId = value(env, 'CATATAN_BOOTSTRAP_ACCOUNT_ID').replace(/\D/g, '');
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(supabaseUrl)) {
    return new Response(JSON.stringify({ error: 'Environment SUPABASE_URL belum terisi atau formatnya tidak valid.' }), { status: 503, headers });
  }
  if (!/^(sb_publishable_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)$/.test(publishableKey)) {
    return new Response(JSON.stringify({ error: 'Environment SUPABASE_PUBLISHABLE_KEY belum terisi dengan Publishable Key yang benar.' }), { status: 503, headers });
  }
  return new Response(JSON.stringify({
    ok: true,
    supabase_url: supabaseUrl,
    publishable_key: publishableKey,
    default_account_id: /^\d{8,16}$/.test(defaultAccountId) ? defaultAccountId : '',
  }), { status: 200, headers });
}
