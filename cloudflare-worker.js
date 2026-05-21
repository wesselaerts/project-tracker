/**
 * Forge proxy worker — v4 (Claude + Gemini)
 *
 * Routes:
 *   /claude/*            → api.anthropic.com (Claude AI coach)
 *   /gemini/messages     → generativelanguage.googleapis.com (Gemini, Anthropic-compatible shape)
 *   /notif/*             → Web Push notifications endpoints
 *   /forge-data/*        → Forge data export voor andere apps
 *   /strava/* /withings/* → OAuth flows voor externe data-bronnen
 *   alles anders         → log.concept2.com (Concept2 Logbook API)
 *
 * Vereiste configuratie:
 *
 * Variables and Secrets (Settings → Variables and Secrets):
 *   CLAUDE_API_KEY         (Secret)  — voor Claude (Anthropic)
 *   GEMINI_API_KEY         (Secret)  — voor Gemini (Google AI Studio)
 *   VAPID_PUBLIC_KEY       (Plain)   — base64url string van VAPID public key (raw 65 bytes uncompressed)
 *   VAPID_PRIVATE_KEY      (Secret)  — base64url string van VAPID private key (raw 32 bytes)
 *   VAPID_SUBJECT          (Plain)   — mailto:jouw@email.nl
 *   FORGE_DATA_API_KEY     (Secret)  — voor /forge-data/fetch authenticatie
 *
 * KV Namespace Binding (Settings → Variables and Secrets):
 *   SUBSCRIPTIONS          — KV namespace voor subscription opslag
 *
 * Cron Trigger (Settings → Triggers):
 *   "0 6 * * 1"            — elke maandag 06:00 UTC
 */

const CONCEPT2_TARGET = 'https://log.concept2.com';
const CLAUDE_TARGET = 'https://api.anthropic.com';
const GEMINI_TARGET = 'https://generativelanguage.googleapis.com';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Accept, Content-Type, anthropic-version, x-api-key',
  'Access-Control-Max-Age': '86400'
};

function withCors(headers = {}) {
  const h = new Headers(headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) h.set(k, v);
  return h;
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: withCors({ 'Content-Type': 'application/json' })
  });
}

// ============ BASE64URL ============

function b64urlEncode(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let str = '';
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ============ VAPID JWT ============

async function importVapidPrivateKey(rawPrivKeyB64url, publicKeyB64url) {
  const d = b64urlDecode(rawPrivKeyB64url);
  const pub = b64urlDecode(publicKeyB64url);
  const xy = pub.slice(1); // strip 0x04 prefix
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    d: b64urlEncode(d),
    x: b64urlEncode(xy.slice(0, 32)),
    y: b64urlEncode(xy.slice(32, 64)),
    ext: true
  };
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']
  );
}

async function createVapidAuthHeader(endpoint, env) {
  const audience = new URL(endpoint).origin;
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = {
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT || 'mailto:noreply@forge.local'
  };
  const enc = new TextEncoder();
  const headerB64 = b64urlEncode(enc.encode(JSON.stringify(header)));
  const payloadB64 = b64urlEncode(enc.encode(JSON.stringify(payload)));
  const unsigned = `${headerB64}.${payloadB64}`;

  const privKey = await importVapidPrivateKey(env.VAPID_PRIVATE_KEY, env.VAPID_PUBLIC_KEY);
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privKey,
    enc.encode(unsigned)
  );
  return `vapid t=${unsigned}.${b64urlEncode(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

// ============ WEB PUSH ENCRYPTION (aes128gcm, RFC 8291) ============

async function hkdfDerive(saltOrKey, ikm, info, length) {
  const ikmKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', salt: saltOrKey, info, hash: 'SHA-256' },
    ikmKey, length * 8
  ));
}

async function encryptWebPushPayload(payload, p256dhB64, authB64) {
  const enc = new TextEncoder();
  const ua_public_raw = b64urlDecode(p256dhB64);
  const auth_secret = b64urlDecode(authB64);

  const uaPubKey = await crypto.subtle.importKey(
    'raw', ua_public_raw,
    { name: 'ECDH', namedCurve: 'P-256' },
    true, []
  );

  const asKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveBits']
  );
  const as_public_raw = new Uint8Array(await crypto.subtle.exportKey('raw', asKeyPair.publicKey));

  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'ECDH', public: uaPubKey },
    asKeyPair.privateKey, 256
  ));

  // IKM = HKDF(auth_secret, shared, "WebPush: info\0" || ua_public || as_public, 32)
  const info1Prefix = enc.encode('WebPush: info\0');
  const info1 = new Uint8Array(info1Prefix.length + ua_public_raw.length + as_public_raw.length);
  info1.set(info1Prefix, 0);
  info1.set(ua_public_raw, info1Prefix.length);
  info1.set(as_public_raw, info1Prefix.length + ua_public_raw.length);
  const IKM = await hkdfDerive(auth_secret, shared, info1, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const CEK = await hkdfDerive(salt, IKM, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const NONCE = await hkdfDerive(salt, IKM, enc.encode('Content-Encoding: nonce\0'), 12);

  const payloadBytes = typeof payload === 'string' ? enc.encode(payload) : payload;
  const plaintext = new Uint8Array(payloadBytes.length + 1);
  plaintext.set(payloadBytes, 0);
  plaintext[payloadBytes.length] = 0x02;

  const cekKey = await crypto.subtle.importKey('raw', CEK, { name: 'AES-GCM', length: 128 }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: NONCE },
    cekKey, plaintext
  ));

  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096, false);

  const header = new Uint8Array(16 + 4 + 1 + as_public_raw.length);
  header.set(salt, 0);
  header.set(rs, 16);
  header[20] = as_public_raw.length;
  header.set(as_public_raw, 21);

  const result = new Uint8Array(header.length + ciphertext.length);
  result.set(header, 0);
  result.set(ciphertext, header.length);
  return result;
}

async function sendWebPush(subscription, payloadObj, env, options = {}) {
  const payload = JSON.stringify(payloadObj);
  const encrypted = await encryptWebPushPayload(payload, subscription.keys.p256dh, subscription.keys.auth);
  const vapidAuth = await createVapidAuthHeader(subscription.endpoint, env);

  const response = await fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': vapidAuth,
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': String(options.ttl || 86400),
      'Urgency': options.urgency || 'normal'
    },
    body: encrypted
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    const err = new Error(`Push failed ${response.status}: ${text}`);
    err.status = response.status;
    throw err;
  }
  return response;
}

// ============ KV SUBSCRIPTION STORAGE ============

async function subscriptionKey(endpoint) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));
  return 'sub:' + b64urlEncode(hash).slice(0, 20);
}

async function saveSubscription(env, subscription, preferences) {
  if (!env.SUBSCRIPTIONS) throw new Error('KV binding SUBSCRIPTIONS niet geconfigureerd');
  const key = await subscriptionKey(subscription.endpoint);
  await env.SUBSCRIPTIONS.put(key, JSON.stringify({
    subscription, preferences: preferences || {}, savedAt: new Date().toISOString()
  }));
  return key;
}

async function removeSubscription(env, endpoint) {
  if (!env.SUBSCRIPTIONS) throw new Error('KV binding SUBSCRIPTIONS niet geconfigureerd');
  await env.SUBSCRIPTIONS.delete(await subscriptionKey(endpoint));
}

async function listSubscriptions(env) {
  if (!env.SUBSCRIPTIONS) return [];
  const list = await env.SUBSCRIPTIONS.list({ prefix: 'sub:' });
  const results = [];
  for (const k of list.keys) {
    const data = await env.SUBSCRIPTIONS.get(k.name);
    if (data) {
      try { results.push({ key: k.name, ...JSON.parse(data) }); } catch {}
    }
  }
  return results;
}

// ============ NOTIF ENDPOINT HANDLER ============

async function handleNotif(request, env, url) {
  const path = url.pathname.replace(/^\/notif/, '');
  if (request.method !== 'POST') return jsonResponse({ error: 'POST only' }, 405);

  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: 'Invalid JSON' }, 400); }

  if (path === '/subscribe') {
    const { subscription, preferences } = body;
    if (!subscription?.endpoint || !subscription?.keys?.p256dh || !subscription?.keys?.auth) {
      return jsonResponse({ error: 'Invalid subscription' }, 400);
    }
    try {
      const key = await saveSubscription(env, subscription, preferences);
      return jsonResponse({ ok: true, key });
    } catch (e) {
      return jsonResponse({ error: e.message }, 500);
    }
  }

  if (path === '/unsubscribe') {
    const { endpoint } = body;
    if (!endpoint) return jsonResponse({ error: 'Missing endpoint' }, 400);
    try {
      await removeSubscription(env, endpoint);
      return jsonResponse({ ok: true });
    } catch (e) {
      return jsonResponse({ error: e.message }, 500);
    }
  }

  if (path === '/send' || path === '/test') {
    if (!env.VAPID_PRIVATE_KEY || !env.VAPID_PUBLIC_KEY) {
      return jsonResponse({ error: 'VAPID keys not configured' }, 500);
    }
    const { subscription, title, message, tag, url: clickUrl } = body;
    if (!subscription) return jsonResponse({ error: 'Missing subscription' }, 400);
    try {
      const resp = await sendWebPush(subscription, {
        title: title || 'Forge',
        body: message || '',
        tag: tag || 'forge',
        url: clickUrl || './'
      }, env);
      return jsonResponse({ ok: true, status: resp.status });
    } catch (e) {
      return jsonResponse({ error: e.message }, 500);
    }
  }

  return jsonResponse({ error: 'Unknown endpoint' }, 404);
}

// ============ WITHINGS OAUTH + SYNC ============

const WITHINGS_AUTH_URL = 'https://account.withings.com/oauth2_user/authorize2';
const WITHINGS_TOKEN_URL = 'https://wbsapi.withings.net/v2/oauth2';
const WITHINGS_MEASURE_URL = 'https://wbsapi.withings.net/measure';

const WITHINGS_MEASURE_TYPES = {
  1: 'weight',         // kg
  5: 'fatFreeMass',    // kg
  6: 'fatRatio',       // %
  8: 'fatMass',        // kg
  11: 'pulse',         // bpm (heart pulse standing)
  76: 'muscleMass',    // kg
  77: 'hydration',     // kg
  88: 'boneMass'       // kg
};

function getWorkerOrigin(request) {
  return new URL(request.url).origin;
}

async function withingsExchangeCode(code, redirectUri, env) {
  const body = new URLSearchParams({
    action: 'requesttoken',
    grant_type: 'authorization_code',
    client_id: env.WITHINGS_CLIENT_ID,
    client_secret: env.WITHINGS_CLIENT_SECRET,
    code,
    redirect_uri: redirectUri
  });
  const resp = await fetch(WITHINGS_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });
  const data = await resp.json();
  if (data.status !== 0) {
    throw new Error('Withings token exchange failed: ' + JSON.stringify(data));
  }
  return {
    accessToken: data.body.access_token,
    refreshToken: data.body.refresh_token,
    expiresAt: Date.now() + (data.body.expires_in * 1000),
    userId: data.body.userid
  };
}

async function withingsRefreshTokens(tokens, env) {
  const body = new URLSearchParams({
    action: 'requesttoken',
    grant_type: 'refresh_token',
    client_id: env.WITHINGS_CLIENT_ID,
    client_secret: env.WITHINGS_CLIENT_SECRET,
    refresh_token: tokens.refreshToken
  });
  const resp = await fetch(WITHINGS_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });
  const data = await resp.json();
  if (data.status !== 0) throw new Error('Withings token refresh failed: ' + JSON.stringify(data));
  return {
    accessToken: data.body.access_token,
    refreshToken: data.body.refresh_token,
    expiresAt: Date.now() + (data.body.expires_in * 1000),
    userId: data.body.userid
  };
}

async function getValidWithingsTokens(env) {
  if (!env.SUBSCRIPTIONS) throw new Error('KV not bound');
  const tokensJson = await env.SUBSCRIPTIONS.get('withings:tokens');
  if (!tokensJson) return null;
  let tokens = JSON.parse(tokensJson);
  // Refresh als bijna verlopen
  if (tokens.expiresAt < Date.now() + 60_000) {
    tokens = await withingsRefreshTokens(tokens, env);
    await env.SUBSCRIPTIONS.put('withings:tokens', JSON.stringify(tokens));
  }
  return tokens;
}

function parseWithingsMeasures(measuregrps) {
  return (measuregrps || []).map(grp => {
    const date = new Date(grp.date * 1000);
    const isoDate = date.getFullYear() + '-' +
      String(date.getMonth() + 1).padStart(2, '0') + '-' +
      String(date.getDate()).padStart(2, '0');
    const m = {
      externalId: 'withings-' + grp.grpid,
      date: isoDate,
      timestamp: grp.date * 1000,
      source: 'withings'
    };
    for (const measure of grp.measures || []) {
      const key = WITHINGS_MEASURE_TYPES[measure.type];
      if (!key) continue;
      m[key] = measure.value * Math.pow(10, measure.unit);
    }
    return m;
  }).sort((a, b) => a.timestamp - b.timestamp);
}

async function handleWithings(request, env, url) {
  const path = url.pathname.replace(/^\/withings/, '');

  if (!env.WITHINGS_CLIENT_ID || !env.WITHINGS_CLIENT_SECRET) {
    return jsonResponse({ error: 'WITHINGS_NOT_CONFIGURED', message: 'Add WITHINGS_CLIENT_ID and WITHINGS_CLIENT_SECRET to Worker' }, 500);
  }
  if (!env.SUBSCRIPTIONS) {
    return jsonResponse({ error: 'KV_NOT_BOUND', message: 'SUBSCRIPTIONS KV namespace not bound' }, 500);
  }

  // ----- /withings/auth-url -----
  if (path === '/auth-url') {
    const returnTo = url.searchParams.get('return_to') || '';
    const state = btoa(JSON.stringify({ returnTo, ts: Date.now() })).replace(/=+$/, '');
    const redirectUri = getWorkerOrigin(request) + '/withings/callback';
    const authUrl = new URL(WITHINGS_AUTH_URL);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', env.WITHINGS_CLIENT_ID);
    authUrl.searchParams.set('scope', 'user.metrics');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('state', state);
    return jsonResponse({ url: authUrl.toString(), redirectUri });
  }

  // ----- /withings/callback -----
  if (path === '/callback') {
    const code = url.searchParams.get('code');
    const stateRaw = url.searchParams.get('state') || '';
    if (!code) {
      return new Response('Withings koppeling mislukt: geen code ontvangen.', { status: 400 });
    }
    let returnTo = '';
    try {
      const padded = stateRaw + '='.repeat((4 - stateRaw.length % 4) % 4);
      const stateData = JSON.parse(atob(padded));
      returnTo = stateData.returnTo || '';
    } catch { /* ignore state errors */ }

    try {
      const redirectUri = getWorkerOrigin(request) + '/withings/callback';
      const tokens = await withingsExchangeCode(code, redirectUri, env);
      await env.SUBSCRIPTIONS.put('withings:tokens', JSON.stringify(tokens));

      // Redirect terug naar Forge met success-hash
      const target = returnTo || 'https://wesselaerts.github.io/forge-tracker/';
      const sep = target.includes('#') ? '&' : '#';
      return Response.redirect(target + sep + 'withings=connected', 302);
    } catch (e) {
      return new Response('Token exchange mislukt: ' + e.message, { status: 500 });
    }
  }

  // ----- /withings/status -----
  if (path === '/status') {
    const tokensJson = await env.SUBSCRIPTIONS.get('withings:tokens');
    const lastSync = await env.SUBSCRIPTIONS.get('withings:last_sync');
    return jsonResponse({
      connected: !!tokensJson,
      userId: tokensJson ? JSON.parse(tokensJson).userId : null,
      lastSyncAt: lastSync ? parseInt(lastSync) : null
    });
  }

  // ----- /withings/disconnect -----
  if (path === '/disconnect') {
    if (request.method !== 'POST') return jsonResponse({ error: 'POST only' }, 405);
    await env.SUBSCRIPTIONS.delete('withings:tokens');
    await env.SUBSCRIPTIONS.delete('withings:last_sync');
    return jsonResponse({ ok: true });
  }

  // ----- /withings/sync -----
  if (path === '/sync') {
    const tokens = await getValidWithingsTokens(env);
    if (!tokens) return jsonResponse({ error: 'NOT_CONNECTED', message: 'Withings niet gekoppeld' }, 401);

    // Bepaal start-tijd: laatste sync of 90 dagen geleden voor initial
    const lastSyncStr = await env.SUBSCRIPTIONS.get('withings:last_sync');
    const lastSync = lastSyncStr ? parseInt(lastSyncStr) : Math.floor(Date.now() / 1000) - (90 * 24 * 3600);

    const measUrl = new URL(WITHINGS_MEASURE_URL);
    measUrl.searchParams.set('action', 'getmeas');
    measUrl.searchParams.set('meastypes', Object.keys(WITHINGS_MEASURE_TYPES).join(','));
    measUrl.searchParams.set('category', '1'); // 1 = real measurements, 2 = goals
    measUrl.searchParams.set('lastupdate', String(lastSync));

    const measResp = await fetch(measUrl.toString(), {
      headers: { 'Authorization': 'Bearer ' + tokens.accessToken }
    });
    const measData = await measResp.json();
    if (measData.status !== 0) {
      return jsonResponse({ error: 'MEASURE_FETCH_FAILED', details: measData }, 502);
    }

    const measurements = parseWithingsMeasures(measData.body.measuregrps);
    await env.SUBSCRIPTIONS.put('withings:last_sync', String(Math.floor(Date.now() / 1000)));

    return jsonResponse({
      ok: true,
      measurements,
      count: measurements.length,
      syncedAt: Date.now()
    });
  }

  return jsonResponse({ error: 'Unknown endpoint: ' + path }, 404);
}

// ============ FORGE DATA EXPORT API ============
// Maakt Forge-data (schedule + sessions + today's plan) beschikbaar voor andere apps
// die ook door de gebruiker worden ontwikkeld.

async function handleForgeData(request, env, url) {
  const path = url.pathname.replace(/^\/forge-data/, '');

  if (!env.SUBSCRIPTIONS) {
    return jsonResponse({ error: 'KV_NOT_BOUND' }, 500);
  }

  // ----- POST /forge-data/sync -----
  // Forge stuurt zijn data hierheen (auto-sync bij save/open)
  if (path === '/sync' && request.method === 'POST') {
    // Optioneel: simple auth via header (we vertrouwen Forge zelf via Worker URL knowledge)
    try {
      const data = await request.json();
      // Validate shape
      if (typeof data !== 'object' || data === null) {
        return jsonResponse({ error: 'INVALID_PAYLOAD' }, 400);
      }
      const stored = {
        exportedAt: new Date().toISOString(),
        version: 1,
        schedule: data.schedule || {},
        todaysPlan: data.todaysPlan || null,
        recentSessions: Array.isArray(data.recentSessions) ? data.recentSessions : []
      };
      await env.SUBSCRIPTIONS.put('forge:exported', JSON.stringify(stored));
      return jsonResponse({ ok: true, exportedAt: stored.exportedAt });
    } catch (e) {
      return jsonResponse({ error: 'PARSE_ERROR', message: e.message }, 400);
    }
  }

  // ----- GET /forge-data/fetch?key=<API_KEY> -----
  // Andere app fetcht hier de data met API key
  if (path === '/fetch' && request.method === 'GET') {
    if (!env.FORGE_DATA_API_KEY) {
      return jsonResponse({ error: 'API_KEY_NOT_CONFIGURED', message: 'Add FORGE_DATA_API_KEY to Worker secrets' }, 500);
    }
    // Accept key via ?key= or Authorization: Bearer
    const queryKey = url.searchParams.get('key');
    const authHeader = request.headers.get('Authorization') || '';
    const bearerKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const providedKey = queryKey || bearerKey;
    if (!providedKey || providedKey !== env.FORGE_DATA_API_KEY) {
      return jsonResponse({ error: 'UNAUTHORIZED' }, 401);
    }
    const stored = await env.SUBSCRIPTIONS.get('forge:exported');
    if (!stored) {
      return jsonResponse({
        exportedAt: null,
        version: 1,
        schedule: {},
        todaysPlan: null,
        recentSessions: [],
        message: 'No data synced yet. Open Forge to trigger first sync.'
      });
    }
    return jsonResponse(JSON.parse(stored));
  }

  // ----- GET /forge-data/status -----
  // Voor debugging: check of er data is en hoe oud
  if (path === '/status') {
    const stored = await env.SUBSCRIPTIONS.get('forge:exported');
    if (!stored) return jsonResponse({ hasData: false });
    const data = JSON.parse(stored);
    return jsonResponse({
      hasData: true,
      exportedAt: data.exportedAt,
      scheduleKeys: Object.keys(data.schedule || {}),
      hasTodaysPlan: !!data.todaysPlan,
      sessionsCount: (data.recentSessions || []).length,
      apiKeyConfigured: !!env.FORGE_DATA_API_KEY
    });
  }

  return jsonResponse({ error: 'Unknown endpoint: ' + path }, 404);
}

// ============ ALLICO DATA EXPORT API ============
// Maakt Allico (MCX Quiz Trainer) sessies beschikbaar voor Kantoor TARS.
// Allico pusht zijn sessions naar /allico-data/sync, Kantoor TARS leest via /allico-data/fetch.

async function handleAllico(request, env, url) {
  const path = url.pathname.replace(/^\/allico-data/, '');

  if (!env.SUBSCRIPTIONS) {
    return jsonResponse({ error: 'KV_NOT_BOUND' }, 500);
  }

  // ----- POST /allico-data/sync -----
  // Allico pusht zijn sessie-data hierheen
  if (path === '/sync' && request.method === 'POST') {
    try {
      const data = await request.json();
      if (typeof data !== 'object' || data === null) {
        return jsonResponse({ error: 'INVALID_PAYLOAD' }, 400);
      }
      const stored = {
        exportedAt: new Date().toISOString(),
        version: 1,
        sessions: Array.isArray(data.sessions) ? data.sessions : []
      };
      await env.SUBSCRIPTIONS.put('allico:exported', JSON.stringify(stored));
      return jsonResponse({ ok: true, exportedAt: stored.exportedAt, count: stored.sessions.length });
    } catch (e) {
      return jsonResponse({ error: 'PARSE_ERROR', message: e.message }, 400);
    }
  }

  // ----- GET /allico-data/fetch -----
  // Kantoor TARS haalt hier de data op
  if (path === '/fetch' && request.method === 'GET') {
    if (!env.ALLICO_DATA_API_KEY) {
      return jsonResponse({ error: 'API_KEY_NOT_CONFIGURED', message: 'Add ALLICO_DATA_API_KEY to Worker secrets' }, 500);
    }
    const queryKey = url.searchParams.get('key');
    const authHeader = request.headers.get('Authorization') || '';
    const bearerKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const providedKey = queryKey || bearerKey;
    if (!providedKey || providedKey !== env.ALLICO_DATA_API_KEY) {
      return jsonResponse({ error: 'UNAUTHORIZED' }, 401);
    }
    const stored = await env.SUBSCRIPTIONS.get('allico:exported');
    if (!stored) {
      return jsonResponse({
        exportedAt: null,
        version: 1,
        sessions: [],
        message: 'No Allico data synced yet. Open Allico to trigger first sync.'
      });
    }
    return jsonResponse(JSON.parse(stored));
  }

  // ----- GET /allico-data/status -----
  if (path === '/status') {
    const stored = await env.SUBSCRIPTIONS.get('allico:exported');
    if (!stored) return jsonResponse({ hasData: false, apiKeyConfigured: !!env.ALLICO_DATA_API_KEY });
    const data = JSON.parse(stored);
    return jsonResponse({
      hasData: true,
      exportedAt: data.exportedAt,
      sessionsCount: (data.sessions || []).length,
      apiKeyConfigured: !!env.ALLICO_DATA_API_KEY
    });
  }

  return jsonResponse({ error: 'Unknown endpoint: ' + path }, 404);
}

// ============ STRAVA OAUTH + SYNC ============

const STRAVA_AUTH_URL = 'https://www.strava.com/oauth/authorize';
const STRAVA_TOKEN_URL = 'https://www.strava.com/api/v3/oauth/token';
const STRAVA_ACTIVITIES_URL = 'https://www.strava.com/api/v3/athlete/activities';

// Default activity types to sync. Forge gebruikt deze als filter.
// Extra types kun je later toevoegen via een Forge UI of hier.
const STRAVA_DEFAULT_TYPES = new Set([
  'Run', 'TrailRun', 'VirtualRun',
  'Walk',
  'Ride', 'VirtualRide', 'EBikeRide',
  'Hike'
]);

// Strava type → Forge cardioType
function mapStravaType(type) {
  const map = {
    'Run': 'run',
    'TrailRun': 'run',
    'VirtualRun': 'run',
    'Walk': 'walk',
    'Hike': 'hike',
    'Ride': 'bike',
    'VirtualRide': 'bike',
    'EBikeRide': 'bike'
  };
  return map[type] || 'cardio';
}

async function stravaExchangeCode(code, env) {
  const body = new URLSearchParams({
    client_id: env.STRAVA_CLIENT_ID,
    client_secret: env.STRAVA_CLIENT_SECRET,
    code,
    grant_type: 'authorization_code'
  });
  const resp = await fetch(STRAVA_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error('Strava token exchange failed: ' + text);
  }
  const data = await resp.json();
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: data.expires_at * 1000, // Strava gives unix seconds
    athleteId: data.athlete?.id,
    athleteName: data.athlete ? `${data.athlete.firstname || ''} ${data.athlete.lastname || ''}`.trim() : null
  };
}

async function stravaRefreshTokens(tokens, env) {
  const body = new URLSearchParams({
    client_id: env.STRAVA_CLIENT_ID,
    client_secret: env.STRAVA_CLIENT_SECRET,
    refresh_token: tokens.refreshToken,
    grant_type: 'refresh_token'
  });
  const resp = await fetch(STRAVA_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error('Strava token refresh failed: ' + text);
  }
  const data = await resp.json();
  return {
    ...tokens,
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: data.expires_at * 1000
  };
}

async function getValidStravaTokens(env) {
  if (!env.SUBSCRIPTIONS) throw new Error('KV not bound');
  const tokensJson = await env.SUBSCRIPTIONS.get('strava:tokens');
  if (!tokensJson) return null;
  let tokens = JSON.parse(tokensJson);
  // Refresh als bijna verlopen (binnen 5 min)
  if (tokens.expiresAt < Date.now() + 5 * 60_000) {
    tokens = await stravaRefreshTokens(tokens, env);
    await env.SUBSCRIPTIONS.put('strava:tokens', JSON.stringify(tokens));
  }
  return tokens;
}

function parseStravaActivity(act) {
  // Map Strava activity → Forge cardio session shape
  const startDate = new Date(act.start_date_local || act.start_date);
  const isoDate = startDate.getFullYear() + '-' +
    String(startDate.getMonth() + 1).padStart(2, '0') + '-' +
    String(startDate.getDate()).padStart(2, '0');

  return {
    externalId: 'strava-' + act.id,
    stravaId: act.id,
    date: isoDate,
    timestamp: startDate.getTime(),
    type: 'cardio',
    cardioType: mapStravaType(act.type),
    stravaType: act.type,
    name: act.name || act.type,
    durationMin: Math.round((act.moving_time || 0) / 60),
    elapsedMin: Math.round((act.elapsed_time || 0) / 60),
    distanceKm: act.distance ? +(act.distance / 1000).toFixed(2) : null,
    distanceMeters: act.distance || null,
    avgHr: act.average_heartrate || null,
    maxHr: act.max_heartrate || null,
    avgSpeedMs: act.average_speed || null,
    maxSpeedMs: act.max_speed || null,
    avgPaceSecPerKm: act.average_speed ? Math.round(1000 / act.average_speed) : null,
    elevationGain: act.total_elevation_gain || null,
    calories: act.calories || act.kilojoules || null,
    polyline: act.map?.summary_polyline || null,
    sportType: act.sport_type || act.type,
    source: 'strava'
  };
}

async function handleStrava(request, env, url) {
  const path = url.pathname.replace(/^\/strava/, '');

  if (!env.STRAVA_CLIENT_ID || !env.STRAVA_CLIENT_SECRET) {
    return jsonResponse({ error: 'STRAVA_NOT_CONFIGURED', message: 'Add STRAVA_CLIENT_ID and STRAVA_CLIENT_SECRET to Worker' }, 500);
  }
  if (!env.SUBSCRIPTIONS) {
    return jsonResponse({ error: 'KV_NOT_BOUND', message: 'SUBSCRIPTIONS KV namespace not bound' }, 500);
  }

  // ----- /strava/auth-url -----
  if (path === '/auth-url') {
    const returnTo = url.searchParams.get('return_to') || '';
    const state = btoa(JSON.stringify({ returnTo, ts: Date.now() })).replace(/=+$/, '');
    const redirectUri = getWorkerOrigin(request) + '/strava/callback';
    const authUrl = new URL(STRAVA_AUTH_URL);
    authUrl.searchParams.set('client_id', env.STRAVA_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('approval_prompt', 'auto');
    authUrl.searchParams.set('scope', 'activity:read_all');
    authUrl.searchParams.set('state', state);
    return jsonResponse({ url: authUrl.toString(), redirectUri });
  }

  // ----- /strava/callback -----
  if (path === '/callback') {
    const code = url.searchParams.get('code');
    const error = url.searchParams.get('error');
    const stateRaw = url.searchParams.get('state') || '';
    if (error) {
      return new Response(`Strava koppeling geweigerd: ${error}. Probeer opnieuw via Forge.`, { status: 400 });
    }
    if (!code) {
      return new Response('Strava koppeling mislukt: geen code ontvangen.', { status: 400 });
    }
    let returnTo = '';
    try {
      const padded = stateRaw + '='.repeat((4 - stateRaw.length % 4) % 4);
      const stateData = JSON.parse(atob(padded));
      returnTo = stateData.returnTo || '';
    } catch { /* ignore */ }

    try {
      const tokens = await stravaExchangeCode(code, env);
      await env.SUBSCRIPTIONS.put('strava:tokens', JSON.stringify(tokens));

      const target = returnTo || 'https://wesselaerts.github.io/forge-tracker/';
      const sep = target.includes('#') ? '&' : '#';
      return Response.redirect(target + sep + 'strava=connected', 302);
    } catch (e) {
      return new Response('Strava token exchange mislukt: ' + e.message, { status: 500 });
    }
  }

  // ----- /strava/status -----
  if (path === '/status') {
    const tokensJson = await env.SUBSCRIPTIONS.get('strava:tokens');
    const lastSync = await env.SUBSCRIPTIONS.get('strava:last_sync');
    let athleteInfo = null;
    if (tokensJson) {
      const t = JSON.parse(tokensJson);
      athleteInfo = { athleteId: t.athleteId, athleteName: t.athleteName };
    }
    return jsonResponse({
      connected: !!tokensJson,
      athlete: athleteInfo,
      lastSyncAt: lastSync ? parseInt(lastSync) : null
    });
  }

  // ----- /strava/disconnect -----
  if (path === '/disconnect') {
    if (request.method !== 'POST') return jsonResponse({ error: 'POST only' }, 405);
    await env.SUBSCRIPTIONS.delete('strava:tokens');
    await env.SUBSCRIPTIONS.delete('strava:last_sync');
    return jsonResponse({ ok: true });
  }

  // ----- /strava/sync -----
  if (path === '/sync') {
    const tokens = await getValidStravaTokens(env);
    if (!tokens) return jsonResponse({ error: 'NOT_CONNECTED', message: 'Strava niet gekoppeld' }, 401);

    // Bepaal start-tijd: laatste sync of 90 dagen geleden voor initial
    const lastSyncStr = await env.SUBSCRIPTIONS.get('strava:last_sync');
    const after = lastSyncStr
      ? parseInt(lastSyncStr)
      : Math.floor(Date.now() / 1000) - (90 * 24 * 3600);

    // Strava: paginated, max 200 per page. Voor één gebruiker meestal genoeg in 1 page.
    const activities = [];
    let page = 1;
    const perPage = 100;
    while (page <= 5) { // max 5 pages = 500 activities, ruim voor onze use case
      const apiUrl = new URL(STRAVA_ACTIVITIES_URL);
      apiUrl.searchParams.set('after', String(after));
      apiUrl.searchParams.set('per_page', String(perPage));
      apiUrl.searchParams.set('page', String(page));
      const resp = await fetch(apiUrl.toString(), {
        headers: { 'Authorization': 'Bearer ' + tokens.accessToken }
      });
      if (!resp.ok) {
        const text = await resp.text();
        return jsonResponse({ error: 'STRAVA_FETCH_FAILED', status: resp.status, body: text }, 502);
      }
      const data = await resp.json();
      if (!Array.isArray(data) || data.length === 0) break;
      activities.push(...data);
      if (data.length < perPage) break;
      page++;
    }

    // Filter by default types
    const filtered = activities.filter(a => STRAVA_DEFAULT_TYPES.has(a.type));
    const parsed = filtered.map(parseStravaActivity).sort((a, b) => a.timestamp - b.timestamp);

    await env.SUBSCRIPTIONS.put('strava:last_sync', String(Math.floor(Date.now() / 1000)));

    return jsonResponse({
      ok: true,
      activities: parsed,
      count: parsed.length,
      totalFetched: activities.length,
      filtered: activities.length - parsed.length,
      syncedAt: Date.now()
    });
  }

  return jsonResponse({ error: 'Unknown endpoint: ' + path }, 404);
}

// ============ CLAUDE HANDLER ============

async function handleClaude(request, env, url) {
  if (!env.CLAUDE_API_KEY) {
    return jsonResponse({
      error: 'CLAUDE_API_KEY_MISSING',
      message: 'Add CLAUDE_API_KEY to this Worker (Settings → Variables and Secrets)'
    }, 500);
  }
  const claudePath = url.pathname.replace(/^\/claude/, '');
  const targetUrl = CLAUDE_TARGET + claudePath + url.search;
  const fwd = new Headers();
  fwd.set('x-api-key', env.CLAUDE_API_KEY);
  fwd.set('anthropic-version', '2023-06-01');
  fwd.set('content-type', 'application/json');
  try {
    const response = await fetch(targetUrl, {
      method: request.method, headers: fwd,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body
    });
    return new Response(response.body, {
      status: response.status, statusText: response.statusText, headers: withCors(response.headers)
    });
  } catch (err) {
    return jsonResponse({ error: 'CLAUDE_FETCH_FAILED', message: String(err) }, 502);
  }
}

// ============ GEMINI HANDLER ============
// Wraps Google's Gemini API in een Anthropic-compatible response shape
// zodat dezelfde frontend code-pad werkt voor beide providers.

async function handleGemini(request, env, url) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'METHOD_NOT_ALLOWED', message: 'Use POST /gemini/messages' }, 405);
  }
  if (!env.GEMINI_API_KEY) {
    return jsonResponse({
      error: 'GEMINI_API_KEY_MISSING',
      message: 'Voeg GEMINI_API_KEY toe aan Worker Secrets'
    }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: 'INVALID_JSON' }, 400);
  }

  const { model = 'gemini-2.5-pro', system, messages, max_tokens = 1024 } = body;
  if (!Array.isArray(messages) || messages.length === 0) {
    return jsonResponse({ error: 'MESSAGES_REQUIRED' }, 400);
  }

  // Convert Anthropic format → Gemini format
  // Anthropic: { system, messages: [{role, content}] }
  // Gemini:    { systemInstruction, contents: [{role, parts:[{text}]}] }
  const contents = messages.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: typeof m.content === 'string' ? m.content : JSON.stringify(m.content) }]
  }));

  const geminiBody = {
    contents,
    generationConfig: {
      maxOutputTokens: max_tokens,
      temperature: 0.7
    }
  };
  if (system) {
    geminiBody.systemInstruction = { parts: [{ text: system }] };
  }

  const geminiUrl = `${GEMINI_TARGET}/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  let resp;
  try {
    resp = await fetch(geminiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': env.GEMINI_API_KEY
      },
      body: JSON.stringify(geminiBody)
    });
  } catch (err) {
    return jsonResponse({ error: 'GEMINI_FETCH_FAILED', message: String(err) }, 502);
  }

  if (!resp.ok) {
    const errText = await resp.text();
    let parsed;
    try { parsed = JSON.parse(errText); } catch {}
    return jsonResponse({
      error: 'GEMINI_API_ERROR',
      status: resp.status,
      message: parsed?.error?.message || errText.slice(0, 500)
    }, resp.status);
  }

  const data = await resp.json();
  // Extract text from Gemini response shape
  const candidate = data.candidates?.[0];
  const text = candidate?.content?.parts?.map(p => p.text || '').join('') || '';
  const finishReason = candidate?.finishReason || 'STOP';

  // Return in Anthropic-compatible shape — frontend merkt geen verschil
  return jsonResponse({
    id: data.responseId || 'gemini-' + Date.now(),
    type: 'message',
    role: 'assistant',
    model,
    content: [{ type: 'text', text }],
    stop_reason: finishReason === 'STOP' ? 'end_turn' : (finishReason === 'MAX_TOKENS' ? 'max_tokens' : finishReason.toLowerCase()),
    usage: {
      input_tokens: data.usageMetadata?.promptTokenCount || 0,
      output_tokens: data.usageMetadata?.candidatesTokenCount || 0
    }
  });
}

async function handleConcept2(request, url) {
  const targetUrl = CONCEPT2_TARGET + url.pathname + url.search;
  const fwd = new Headers();
  for (const [k, v] of request.headers.entries()) {
    if (k.toLowerCase() === 'host') continue;
    fwd.set(k, v);
  }
  try {
    const response = await fetch(targetUrl, {
      method: request.method, headers: fwd,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
      redirect: 'follow'
    });
    return new Response(response.body, {
      status: response.status, statusText: response.statusText, headers: withCors(response.headers)
    });
  } catch (err) {
    return jsonResponse({ error: 'CONCEPT2_FETCH_FAILED', message: String(err) }, 502);
  }
}

// ============ MAIN ============

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: withCors() });
    const url = new URL(request.url);

    if (url.pathname === '/' || url.pathname === '/health') {
      return jsonResponse({
        ok: true, worker: 'forge-proxy', version: 8,
        features: {
          concept2: true,
          claude: !!env.CLAUDE_API_KEY,
          gemini: !!env.GEMINI_API_KEY,
          push: !!(env.VAPID_PRIVATE_KEY && env.VAPID_PUBLIC_KEY && env.SUBSCRIPTIONS),
          withings: !!(env.WITHINGS_CLIENT_ID && env.WITHINGS_CLIENT_SECRET && env.SUBSCRIPTIONS),
          strava: !!(env.STRAVA_CLIENT_ID && env.STRAVA_CLIENT_SECRET && env.SUBSCRIPTIONS),
          forgeDataExport: !!(env.FORGE_DATA_API_KEY && env.SUBSCRIPTIONS),
          allicoDataExport: !!(env.ALLICO_DATA_API_KEY && env.SUBSCRIPTIONS)
        },
        vapidPublicKey: env.VAPID_PUBLIC_KEY || null
      });
    }

    if (url.pathname.startsWith('/forge-data')) return handleForgeData(request, env, url);
    if (url.pathname.startsWith('/allico-data')) return handleAllico(request, env, url);
    if (url.pathname.startsWith('/strava')) return handleStrava(request, env, url);
    if (url.pathname.startsWith('/withings')) return handleWithings(request, env, url);
    if (url.pathname.startsWith('/notif')) return handleNotif(request, env, url);
    if (url.pathname.startsWith('/gemini')) return handleGemini(request, env, url);
    if (url.pathname.startsWith('/claude')) return handleClaude(request, env, url);
    return handleConcept2(request, url);
  },

  // Cron handler — maandag 06:00 UTC = 8:00 winter / 7:00 zomer NL
  async scheduled(event, env, ctx) {
    if (!env.SUBSCRIPTIONS || !env.VAPID_PRIVATE_KEY || !env.VAPID_PUBLIC_KEY) {
      console.warn('Push infra not fully configured');
      return;
    }
    const now = new Date();
    if (now.getUTCDay() !== 1) return; // only monday

    const subs = await listSubscriptions(env);
    let sent = 0, failed = 0;
    for (const record of subs) {
      if (record.preferences?.weeklyReport === false) continue;
      try {
        await sendWebPush(record.subscription, {
          title: 'TARS: weekrapport beschikbaar',
          body: 'Je rapport van vorige week is klaar voor review. Tap om te bekijken.',
          tag: 'weekly-report',
          url: './'
        }, env);
        sent++;
      } catch (e) {
        failed++;
        if (e.status === 410 || e.status === 404) {
          // Subscription gone, remove
          await removeSubscription(env, record.subscription.endpoint).catch(() => {});
        }
        console.error('Push failed:', e.message);
      }
    }
    console.log(`Weekly push: ${sent} sent, ${failed} failed`);
  }
};
