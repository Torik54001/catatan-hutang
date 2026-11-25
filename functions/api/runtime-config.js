// EdgeOne Pages Function: GET /api/runtime-config
// Publishes only the Supabase project URL and the public Publishable Key.
const headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store, max-age=0',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS, HEAD',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
};

const value = (env, name) => String(env?.[name] ?? '').trim();

export async function onRequest(context) {
  const request = context.request;
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });
  if (request.method === 'HEAD') return new Response(null, { status: 204, headers });
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Metode tidak didukung. Gunakan GET.' }), {
      status: 405, headers: { ...headers, Allow: 'GET, HEAD, OPTIONS' },
    });
  }

  const env = context.env || {};
  const supabaseUrl = value(env, 'SUPABASE_URL').replace(/\/$/, '');
  // Backward compatibility with the names already present in the user's EdgeOne panel.
  const publishableKey = value(env, 'SUPABASE_PUBLISHABLE_KEY')
    || value(env, 'SUPABASE_ANON_KEY')
    || (() => {
      try { return JSON.parse(value(env, 'SUPABASE_PUBLISHABLE_KEYS')).default || ''; }
      catch { return ''; }
    })();
  const defaultAccountId = value(env, 'CATATAN_BOOTSTRAP_ACCOUNT_ID').replace(/\D/g, '');

  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(supabaseUrl)) {
    return new Response(JSON.stringify({ error: 'Environment SUPABASE_URL belum terisi atau formatnya tidak valid.' }), { status: 503, headers });
  }
  if (!/^(sb_publishable_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)$/.test(publishableKey)) {
    return new Response(JSON.stringify({ error: 'Environment SUPABASE_PUBLISHABLE_KEY belum terisi. Nama lama SUPABASE_ANON_KEY juga didukung.' }), { status: 503, headers });
  }

  return new Response(JSON.stringify({
    ok: true,
    supabase_url: supabaseUrl,
    publishable_key: publishableKey,
    default_account_id: /^\d{8,16}$/.test(defaultAccountId) ? defaultAccountId : '',
  }), { status: 200, headers });
}
