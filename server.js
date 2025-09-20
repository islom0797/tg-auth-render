// server.js
import express from 'express';
import crypto from 'crypto';
import admin from 'firebase-admin';
import cors from 'cors';

// ---------------- Firebase Admin init ----------------
function loadServiceAccount() {
  const jsonRaw =
    process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON ||
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON ||
    (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64
      ? Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8')
      : null);

  if (!jsonRaw) return null;

  try {
    return JSON.parse(jsonRaw);
  } catch (e) {
    console.error('Failed to parse service account JSON from env:', e.message);
    return null;
  }
}

const svc = loadServiceAccount();
if (admin.apps.length === 0) {
  if (svc) {
    admin.initializeApp({
      credential: admin.credential.cert(svc),
      // databaseURL можно добавить при необходимости:
      // databaseURL: process.env.FIREBASE_DATABASE_URL
    });
    console.log('[firebase] initialized with service account JSON');
  } else {
    // Попытка через Application Default Credentials (если настроено)
    admin.initializeApp();
    console.log('[firebase] initialized with application default credentials');
  }
}

// ---------------- App & middlewares ----------------
const app = express();
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// health
app.get('/healthz', (_req, res) => res.type('text/plain').send('ok'));

// ---------------- Helpers ----------------
function verifyTelegramLogin(data, botToken) {
  if (!botToken) throw new Error('TG_BOT_TOKEN is not set');

  // Срок годности (опционально): 1 сутки
  if (data.auth_date && Math.abs(Date.now() / 1000 - Number(data.auth_date)) > 86400) {
    throw new Error('Telegram auth data expired');
  }

  const secret = crypto.createHash('sha256').update(botToken).digest();
  const check = Object.keys(data)
    .filter((k) => k !== 'hash' && data[k] !== undefined && data[k] !== null)
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join('\n');

  const hmac = crypto.createHmac('sha256', secret).update(check).digest('hex');
  if (hmac !== String(data.hash)) {
    throw new Error('Bad signature');
  }
}

function sanitizeRedirect(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    // Разрешаем только http(s) и вашу кастомную схему zerno://
    if (u.protocol === 'http:' || u.protocol === 'https:') return u.toString();
    if (u.protocol === 'zerno:') return `zerno://${u.host}${u.pathname}${u.search}`;
  } catch (_) {
    // может быть прямая строка вида "zerno://tg-auth"
    if (url.startsWith('zerno://')) return url;
  }
  return null;
}

function makeQuery(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && String(v).length) q.append(k, String(v));
  });
  return q.toString();
}

// ---------------- Main endpoint ----------------
app.all('/auth/telegram/verify', async (req, res) => {
  try {
    const carrier = req.method === 'GET' ? req.query : (req.body || {});
    const redirectRaw = carrier.redirect;
    const state = carrier.state;
    const phone = carrier.phone;

    // Забираем только поля Telegram для проверки подписи
    const tg = {};
    ['id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date', 'hash'].forEach((k) => {
      if (carrier[k] != null) tg[k] = carrier[k];
    });

    // Валидация и подпись
    if (!tg.id || !tg.hash || !tg.auth_date) {
      return res.status(400).send('Missing Telegram fields');
    }
    verifyTelegramLogin(tg, process.env.TG_BOT_TOKEN);

    // Генерация кастомного токена Firebase
    const uid = `tg_${tg.id}`;
    const claims = {
      tg_id: String(tg.id),
      tg_username: tg.username || null,
      tg_name: [tg.first_name || '', tg.last_name || ''].join(' ').trim() || null,
    };
    const customToken = await admin.auth().createCustomToken(uid, claims);

    // Если есть redirect (deeplink) — делаем 302
    const redirect = sanitizeRedirect(redirectRaw);
    if (redirect) {
      const q = makeQuery({
        token: customToken,
        phone,
        state,
      });
      const target = `${redirect}${redirect.includes('?') ? '&' : '?'}${q}`;

      // 302 + HTML фоллбек (на случай странных браузеров)
      res.status(302)
        .set('Location', target)
        .type('text/html')
        .send(
          `<!doctype html><meta http-equiv="refresh" content="0;url='${target}'"/><a href="${target}">Continue</a>`
        );
      return;
    }

    // Fallback — просто вернуть JSON
    res.json({ customToken });
  } catch (e) {
    console.error('[verify] error:', e);
    res.status(400).send(typeof e?.message === 'string' ? e.message : 'Bad request');
  }
});

// Root
app.get('/', (_req, res) => res.type('text/plain').send('Telegram verifier up'));

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server listening on', PORT));
