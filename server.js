// server.js — ESM, Node 18–22, Render OK, с алиасами и правильной верификацией
import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const {
  TG_BOT_TOKEN,
  APP_DEEPLINK = 'zerno://tg-auth',

  // Вариант A: весь JSON ключ одной переменной
  FIREBASE_SERVICE_ACCOUNT_JSON,

  // Вариант B: три отдельных переменных
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,

  // (опц.) Вариант C: JSON в base64
  FIREBASE_SERVICE_ACCOUNT_B64,
} = process.env;

// ===== helpers: загрузка кредов Firebase Admin =====
function loadFirebaseCredentials() {
  if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      const json = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON.replace(/\\n/g, '\n'));
      return { method: 'JSON', projectId: json.project_id, clientEmail: json.client_email, privateKey: json.private_key };
    } catch {}
  }
  if (FIREBASE_SERVICE_ACCOUNT_B64) {
    try {
      const decoded = Buffer.from(FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8');
      const json = JSON.parse(decoded.replace(/\\n/g, '\n'));
      return { method: 'B64', projectId: json.project_id, clientEmail: json.client_email, privateKey: json.private_key };
    } catch {}
  }
  if (FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY) {
    return { method: 'TRIPLE', projectId: FIREBASE_PROJECT_ID, clientEmail: FIREBASE_CLIENT_EMAIL, privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') };
  }
  return null;
}
const creds = loadFirebaseCredentials();

if (!getApps().length && creds) {
  initializeApp({ credential: cert({ projectId: creds.projectId, clientEmail: creds.clientEmail, privateKey: creds.privateKey }) });
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== правильная верификация Telegram =====
const TL_ALLOWED_KEYS = new Set([
  'id',
  'first_name',
  'last_name',
  'username',
  'photo_url',
  'auth_date',
  // иногда приходит allow_write_to_pm
  'allow_write_to_pm',
]);

const TOKEN_SECRET = () =>
  crypto.createHash('sha256').update(TG_BOT_TOKEN || '').digest();

function verifyTelegramAuth(queryObj) {
  // берём ТОЛЬКО поля Telegram (не phone/state/redirect)
  const data = {};
  for (const k of Object.keys(queryObj)) {
    if (k === 'hash') continue;
    if (TL_ALLOWED_KEYS.has(k) && queryObj[k] !== undefined) data[k] = queryObj[k];
  }

  const dataCheckString = Object.keys(data)
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join('\n');

  const hmac = crypto
    .createHmac('sha256', TOKEN_SECRET())
    .update(dataCheckString)
    .digest('hex');

  const ok = hmac === String(queryObj.hash || '').toLowerCase();
  if (!ok) return { ok: false, reason: 'bad-hash' };

  // опционально: проверим «свежесть» (до 1 суток)
  const now = Math.floor(Date.now() / 1000);
  const authDate = Number(queryObj.auth_date || data.auth_date || 0);
  const MAX_AGE_SEC = 60 * 60 * 24; // 24 часа
  if (!authDate || now - authDate > MAX_AGE_SEC) {
    return { ok: false, reason: 'stale' };
  }

  return { ok: true };
}

// --- алиасы старых путей → на /tg/callback ---
function redirectToCallback(req, res) {
  const qs = new URLSearchParams(req.query || {}).toString();
  const target = '/tg/callback' + (qs ? `?${qs}` : '');
  return res.redirect(302, target);
}
app.get('/auth/telegram/verify', redirectToCallback);
app.get('/auth/telegram/callback', redirectToCallback);
app.get('/tg/verify', redirectToCallback);

// ===== основной коллбек =====
app.get('/tg/callback', async (req, res) => {
  try {
    if (!TG_BOT_TOKEN) return res.status(500).send('TG_BOT_TOKEN not configured');
    if (!getApps().length) return res.status(500).send('Firebase Admin is not initialized. Check ENV credentials.');

    const v = verifyTelegramAuth(req.query);
    if (!v.ok) return res.status(403).send(v.reason === 'stale' ? 'Auth expired' : 'Invalid Telegram hash');

    const {
      id,
      first_name,
      last_name,
      username,
      // не телеграмовские, но мы их поддерживаем и игнорируем при верификации:
      phone = '', // ожидаем 998XXXXXXXXX (без '+'), если ты его прокидываешь с хостинга
    } = req.query;

    const uid = `tg_${id}`;
    const name = [first_name, last_name].filter(Boolean).join(' ');
    const claims = {
      tgId: String(id),
      username: username || '',
      phone: phone || '',
      name,
      authProvider: 'telegram',
    };

    const customToken = await getAuth().createCustomToken(uid, claims);

    const deeplink =
      `${APP_DEEPLINK}?token=${encodeURIComponent(customToken)}` +
      `&phone=${encodeURIComponent(phone || '')}` +
      `&name=${encodeURIComponent(name)}`;

    return res.redirect(deeplink);
  } catch (err) {
    console.error('tg/callback error:', err);
    return res.status(500).send('Server error');
  }
});

// простой healthcheck
app.get('/', (_req, res) => res.send('OK'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server started on', port));
