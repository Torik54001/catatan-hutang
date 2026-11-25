/* Konfigurasi alamat layanan CatatHutang Cloud.
 * Publishable Key diambil langsung dari Environment Supabase Edge Function.
 * Jangan pernah menaruh sb_secret / service_role / PIN di file ini.
 */
window.CATATAN_CONFIG = Object.freeze({
  SUPABASE_URL: 'https://qmegieabtojefmnffhnl.supabase.co',
  LOGIN_FUNCTION: 'catat-hutang-login',
  DEFAULT_ACCOUNT_ID: '085182819967'
});
