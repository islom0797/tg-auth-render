// server.js — ESM, Node 18–22 (Render OK) с диагностикой подписи
import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const {
  TG_BOT_TOKEN,
  APP_DEEPLINK = 'zerno://tg-auth',

  FIREBASE_SERVICE_ACCOUNT_JSON,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  FIREBASE_SERVICE_ACCOUNT_B64,

  // включи "1", чтобы протестировать поток без verify (временно!)
  DEBUG_ALLOW_BYPASS = '0',
} = process.env;

// ── helpers: маски для логов ─────────────────────────────────
const maskEmail = (email = '') => {
  const [u, d] = String(email).split('@');
  if (!d) return '***';
  const user = u?.length > 2 ? `${u[0]}***${u[u.length - 1]}` : '***';
  return `${user}@${d}`;
};
const maskKey = (s = '') => (String(s).length < 16 ? '***' : `${s.slice(0, 10)}...${s.slice(-10)}`);

// ── creds loader ─────────────────────────────────────────────
function loadFirebaseCredentials() {
  if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      const json = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON.replace(/\\n/g, '\n'));
      if (!json.project_id || !json.client_email || !json.private_key) throw new Error('missing fields');
      return { method: 'JSON', projectId: json.project_id, clientEmail: json.client_email, privateKey: json.private_key };
    } catch (e) { console.error('[creds] JSON invalid:', e.message); }
  }
  if (FIREBASE_SERVICE_ACCOUNT_B64) {
    try {
      const decoded = Buffer.from(FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8');
      const json = JSON.parse(decoded.replace(/\\n/g, '\n'));
      if (!json.project_id || !json.client_email || !json.private_key) throw new Error('missing fields');
      return { method: 'B64', projectId: json.project_id, clientEmail: json.client_email, privateKey: json.private_key };
    } catch (e) { console.error('[creds] B64 invalid:', e.message); }
  }
  if (FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY) {
    return { method: 'TRIPLE', projectId: FIREBASE_PROJECT_ID, clientEmail: FIREBASE_CLIENT_EMAIL, privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') };
  }
  return null;
}
const creds = loadFirebaseCredentials();

console.log('[env] TG_BOT_TOKEN:', TG_BOT_TOKEN ? 'SET' : 'MISSING');
if (creds) {
  console.log('[env] Firebase creds method:', creds.method);
  console.log('[env] projectId:', creds.projectId);
  console.log('[env] clientEmail:', maskEmail(creds.clientEmail));
  console.log('[env] privateKey:', maskKey(creds.privateKey));
} else {
  console.error('[env] Firebase creds: NOT FOUND');
}
console.log('[env] DEBUG_ALLOW_BYPASS:', DEBUG_ALLOW_BYPASS);

// init firebase-admin
if (!getApps().length && creds) {
  try {
    initializeApp({ credential: cert({ projectId: creds.projectId, clientEmail: creds.clientEmail, privateKey: creds.privateKey }) });
    console.log('[firebase-admin] initializeApp: OK');
  } catch (e) { console.error('[firebase-admin] initializeApp FAILED:', e.message); }
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── diag endpoints ───────────────────────────────────────────
app.get('/_diag', (_req, res) => {
  res.json({
    ok: true,
    tgBotToken: !!TG_BOT_TOKEN,
    firebaseAdminInitialized: !!getApps().length,
    method: creds?.method || null,
    projectId: creds?.projectId || null,
    clientEmailMasked: creds?.clientEmail ? maskEmail(creds.clientEmail) : null,
    privateKeyMasked: creds?.privateKey ? maskKey(creds.privateKey) : null,
    DEBUG_ALLOW_BYPASS: DEBUG_ALLOW_BYPASS === '1',
  });
});

// Для ручной проверки подписи: /_debug-sig?<параметры от TG>
const TL_ALLOWED_KEYS = new Set([
  'id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date', 'allow_write_to_pm',
]);
const tokenSecret = () => crypto.createHash('sha256').update(TG_BOT_TOKEN || '').digest();

function buildDataCheckString(queryObj) {
  const data = {};
  for (const k of Object.keys(queryObj)) {
    if (k === 'hash') continue;
    if (TL_ALLOWED_KEYS.has(k) && queryObj[k] !== undefined) data[k] = String(queryObj[k]);
  }
  const dataCheckString = Object.keys(data).sort().map((k) => `${k}=${data[k]}`).join('\n');
  return { data, dataCheckString };
}

app.get('/_debug-sig', (req, res) => {
  const { data, dataCheckString } = buildDataCheckString(req.query || {});
  const computed = crypto.createHmac('sha256', tokenSecret()).update(dataCheckString).digest('hex');
  const received = String(req.query?.hash || '').toLowerCase();
  res.json({
    ok: true,
    usedKeys: Object.keys(data),
    dataCheckString,
    computedHmac: computed,
    receivedHash: received || null,
    equal: !!received && computed === received,
    note: 'Если equal=false — чаще всего TG_BOT_TOKEN не от того бота, что в data-telegram-login на фронте.',
  });
});

// ── алиасы старых путей на /tg/callback ───────────────────────
function redirectToCallback(req, res) {
  const qs = new URLSearchParams(req.query || {}).toString();
  res.redirect(302, '/tg/callback' + (qs ? `?${qs}` : ''));
}
app.get('/auth/telegram/verify', redirectToCallback);
app.get('/auth/telegram/callback', redirectToCallback);
app.get('/tg/verify', redirectToCallback);

// ── основная верификация ──────────────────────────────────────
function verifyTelegramAuth(queryObj) {
  const { dataCheckString } = buildDataCheckString(queryObj);
  const calc = crypto.createHmac('sha256', tokenSecret()).update(dataCheckString).digest('hex');
  const okHash = calc === String(queryObj.hash || '').toLowerCase();
  if (!okHash) {
    console.warn('[verify] BAD HASH\n  data_check_string:', dataCheckString, '\n  computed:', calc, '\n  received:', queryObj.hash);
    return { ok: false, reason: 'bad-hash' };
  }
  const now = Math.floor(Date.now() / 1000);
  const ts = Number(queryObj.auth_date || 0);
  if (!ts || now - ts > 60 * 60 * 24) return { ok: false, reason: 'stale' };
  return { ok: true };
}

// ── основной callback ─────────────────────────────────────────
app.get('/tg/callback', async (req, res) => {
  try {
    if (!TG_BOT_TOKEN) return res.status(500).send('TG_BOT_TOKEN not configured');
    if (!getApps().length) return res.status(500).send('Firebase Admin is not initialized. Check ENV credentials.');

    // TEMP: байпас (только для теста)
    if (DEBUG_ALLOW_BYPASS === '1' && String(req.query?.skipVerify) === '1') {
      console.warn('[verify] BYPASSED by DEBUG_ALLOW_BYPASS');
    } else {
      const v = verifyTelegramAuth(req.query);
      if (!v.ok) return res.status(403).send(v.reason === 'stale' ? 'Auth expired' : 'Invalid Telegram hash');
    }

    const { id, first_name, last_name, username, phone = '' } = req.query;
    const uid = `tg_${id}`;
    const name = [first_name, last_name].filter(Boolean).join(' ');
    const claims = { tgId: String(id), username: username || '', phone: phone || '', name, authProvider: 'telegram' };

    const customToken = await getAuth().createCustomToken(uid, claims);
    const deeplink =
      `${APP_DEEPLINK}?token=${encodeURIComponent(customToken)}` +
      `&phone=${encodeURIComponent(phone || '')}` +
      `&name=${encodeURIComponent(name)}`;

    res.redirect(deeplink);
  } catch (e) {
    console.error('tg/callback error:', e);
    res.status(500).send('Server error');
  }
});

// healthcheck
app.get('/', (_req, res) => res.send('OK'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server started on', port));
