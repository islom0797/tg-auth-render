// server.js — ESM, Node 18–22, Render OK, с диагностикой ENV
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

  // Вариант A: весь сервис-аккаунт JSON одной переменной
  FIREBASE_SERVICE_ACCOUNT_JSON,

  // Вариант B: три отдельные переменные
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,

  // Вариант C: JSON в base64 (иногда удобнее)
  FIREBASE_SERVICE_ACCOUNT_B64,
} = process.env;

// ─────────────────────────────────────────────────────────────
// Помощники для маскировки секретов в логах
function maskEmail(email = '') {
  const [u, d] = String(email).split('@');
  if (!d) return '***';
  const user = u?.length > 2 ? `${u[0]}***${u[u.length - 1]}` : '***';
  return `${user}@${d}`;
}
function maskKey(k = '') {
  const s = String(k);
  if (s.length < 16) return '***';
  return `${s.slice(0, 10)}...${s.slice(-10)}`; // показываем только хвостики
}
// ─────────────────────────────────────────────────────────────

/** Загружаем креды Firebase Admin из ENV */
function loadFirebaseCredentials() {
  // Приоритет — A: один JSON (строкой)
  if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      const raw = FIREBASE_SERVICE_ACCOUNT_JSON.trim();
      const normalized = raw.replace(/\\n/g, '\n');
      const json = JSON.parse(normalized);
      if (!json.project_id || !json.client_email || !json.private_key) {
        throw new Error('Missing fields in FIREBASE_SERVICE_ACCOUNT_JSON');
      }
      return {
        method: 'JSON',
        projectId: json.project_id,
        clientEmail: json.client_email,
        privateKey: json.private_key,
      };
    } catch (e) {
      console.error('[creds] Invalid FIREBASE_SERVICE_ACCOUNT_JSON:', e.message);
    }
  }

  // Вариант C: JSON в base64
  if (FIREBASE_SERVICE_ACCOUNT_B64) {
    try {
      const decoded = Buffer.from(FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8');
      const normalized = decoded.replace(/\\n/g, '\n');
      const json = JSON.parse(normalized);
      if (!json.project_id || !json.client_email || !json.private_key) {
        throw new Error('Missing fields in FIREBASE_SERVICE_ACCOUNT_B64');
      }
      return {
        method: 'B64',
        projectId: json.project_id,
        clientEmail: json.client_email,
        privateKey: json.private_key,
      };
    } catch (e) {
      console.error('[creds] Invalid FIREBASE_SERVICE_ACCOUNT_B64:', e.message);
    }
  }

  // Фоллбек — B: три переменные
  if (FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY) {
    return {
      method: 'TRIPLE',
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    };
  }

  return null;
}

const creds = loadFirebaseCredentials();

// Диагностика: что увидели из ENV (без секретов)
console.log('[env] TG_BOT_TOKEN:', TG_BOT_TOKEN ? 'SET' : 'MISSING');
if (creds) {
  console.log('[env] Firebase creds method:', creds.method);
  console.log('[env] projectId:', creds.projectId || 'MISSING');
  console.log('[env] clientEmail:', creds.clientEmail ? maskEmail(creds.clientEmail) : 'MISSING');
  console.log('[env] privateKey:', creds.privateKey ? maskKey(creds.privateKey) : 'MISSING');
} else {
  console.error('[env] Firebase creds: NOT FOUND (JSON/B64/TRIPLE all missing or invalid)');
}

// Инициализация Firebase Admin (модульный API)
if (!getApps().length) {
  if (!creds) {
    console.error('Firebase Admin credentials are missing in environment variables.');
  } else {
    try {
      initializeApp({
        credential: cert({
          projectId: creds.projectId,
          clientEmail: creds.clientEmail,
          privateKey: creds.privateKey,
        }),
      });
      console.log('[firebase-admin] initializeApp: OK');
    } catch (e) {
      console.error('[firebase-admin] initializeApp: FAILED:', e.message);
    }
  }
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/** Диагностический эндпойнт */
app.get('/_diag', async (_req, res) => {
  const initialized = !!getApps().length;
  res.json({
    ok: true,
    tgBotToken: !!TG_BOT_TOKEN,
    firebaseAdminInitialized: initialized,
    method: creds?.method || null,
    projectId: creds?.projectId || null,
    clientEmailMasked: creds?.clientEmail ? maskEmail(creds.clientEmail) : null,
    privateKeyMasked: creds?.privateKey ? maskKey(creds.privateKey) : null,
  });
});

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
app.get('/auth/telegram/verify', redirectToCallback);
app.get('/auth/telegram/callback', redirectToCallback);
app.get('/tg/verify', redirectToCallback);

/** Основной callback: браузер → Render → диплинк в приложение */
app.get('/tg/callback', async (req, res) => {
  try {
    if (!TG_BOT_TOKEN) return res.status(500).send('TG_BOT_TOKEN not configured');

    if (!getApps().length) {
      return res.status(500).send('Firebase Admin is not initialized. Check ENV credentials.');
    }

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
