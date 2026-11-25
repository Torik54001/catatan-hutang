/**
 * Catat Hutang Cloud — public runtime configuration for EdgeOne Pages Functions.
 * Route: GET /api/runtime-config
 * Only intentionally public values are returned. Never return the service key or PIN.
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

export async function onRequestGet({ env }) {
  const supabaseUrl = String(env?.SUPABASE_URL || '').trim().replace(/\/$/, '');
  const publishableKey = String(env?.SUPABASE_PUBLISHABLE_KEY || '').trim();
  const defaultAccountId = String(
    env?.CATATAN_DEFAULT_ACCOUNT_ID || env?.CATATAN_BOOTSTRAP_ACCOUNT_ID || '',
  ).replace(/\D/g, '');

  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(supabaseUrl)) {
    return json(503, { error: 'SUPABASE_URL belum diisi atau formatnya tidak valid pada Environment Variables EdgeOne.' });
  }
  if (!publishableKey.startsWith('sb_publishable_')) {
    return json(503, { error: 'SUPABASE_PUBLISHABLE_KEY belum diisi pada Environment Variables EdgeOne.' });
  }

  return json(200, {
    supabase_url: supabaseUrl,
    publishable_key: publishableKey,
    default_account_id: defaultAccountId,
  });
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: { Allow: 'GET, OPTIONS' } });
}

export async function onRequest({ request, env }) {
  if (request.method === 'GET') return onRequestGet({ request, env });
  if (request.method === 'OPTIONS') return onRequestOptions();
  return json(405, { error: 'Metode tidak didukung. Gunakan GET.' });
}
