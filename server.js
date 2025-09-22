// server.js — ESM, Node 18–22, Render OK
import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const {
  // Telegram bot token (обязателен)
  TG_BOT_TOKEN,

  // диплинк обратно в приложение (можно переопределить в ENV)
  APP_DEEPLINK = 'zerno://tg-auth',

  // Вариант А: весь сервис-аккаунт JSON одной переменной
  FIREBASE_SERVICE_ACCOUNT_JSON,

  // Вариант Б: три отдельные переменные (fallback)
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
} = process.env;

/** Загружаем креды Firebase Admin из ENV */
function loadFirebaseCredentials() {
  // Приоритет — один JSON
  if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      const raw = FIREBASE_SERVICE_ACCOUNT_JSON.trim();
      const normalized = raw.replace(/\\n/g, '\n');
      const json = JSON.parse(normalized);
      if (!json.project_id || !json.client_email || !json.private_key) {
        throw new Error('Missing fields in FIREBASE_SERVICE_ACCOUNT_JSON');
      }
      return {
        projectId: json.project_id,
        clientEmail: json.client_email,
        privateKey: json.private_key,
      };
    } catch (e) {
      console.error('Invalid FIREBASE_SERVICE_ACCOUNT_JSON:', e.message);
      // пойдём по варианту Б
    }
  }

  // Фоллбек — три переменные
  if (FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY) {
    return {
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    };
  }

  return null;
}

const creds = loadFirebaseCredentials();

// Инициализация Firebase Admin (модульный API)
if (!getApps().length) {
  if (!creds) {
    console.error('Firebase Admin credentials are missing in environment variables.');
  } else {
    initializeApp({
      credential: cert({
        projectId: creds.projectId,
        clientEmail: creds.clientEmail,
        privateKey: creds.privateKey,
      }),
    });
  }
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/** Проверка подписи Telegram Login Widget */
function verifyTelegramAuth(queryObj) {
  const { hash, ...data } = queryObj;
  const dataCheckString = Object.keys(data)
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join('\n');

  const secretKey = crypto.createHash('sha256').update(TG_BOT_TOKEN || '').digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  return hmac === hash;
}

// --- Алиасы старых путей → на новый обработчик /tg/callback ---
function redirectToCallback(req, res) {
  const qs = new URLSearchParams(req.query || {}).toString();
  const target = '/tg/callback' + (qs ? `?${qs}` : '');
  return res.redirect(302, target);
}

// Часто встречающиеся старые роуты (на случай, если где-то остались ссылки)
app.get('/auth/telegram/verify', redirectToCallback);
app.get('/auth/telegram/callback', redirectToCallback);
app.get('/tg/verify', redirectToCallback);

/** Основной callback: браузер → Render → диплинк в приложение */
app.get('/tg/callback', async (req, res) => {
  try {
    if (!TG_BOT_TOKEN) return res.status(500).send('TG_BOT_TOKEN not configured');
    if (!getApps().length) return res.status(500).send('Firebase Admin is not initialized. Check ENV credentials.');
    if (!verifyTelegramAuth(req.query)) return res.status(403).send('Invalid Telegram hash');

    const {
      id,
      first_name,
      last_name,
      username,
      // photo_url, auth_date — не используем
      phone = '', // можно прокидывать со страницы хостинга как ?phone=998XXXXXXXXX (без '+')
    } = req.query;

    const uid = `tg_${id}`;
    const name = [first_name, last_name].filter(Boolean).join(' ');

    // Кастомные клеймы — не делай их слишком большими
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

app.get('/', (_req, res) => res.send('OK'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server started on', port));
