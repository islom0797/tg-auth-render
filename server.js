// server.js  — ESM, Node 18+ (Render OK)
import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const {
  TG_BOT_TOKEN,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  APP_DEEPLINK = 'zerno://tg-auth',
} = process.env;

// Инициализация Firebase Admin (модульный API)
if (!getApps().length) {
  if (!FIREBASE_PROJECT_ID || !FIREBASE_CLIENT_EMAIL || !FIREBASE_PRIVATE_KEY) {
    console.error('Firebase Admin credentials are missing in environment variables.');
    // Не кидаем ошибку сразу, чтобы Render лог показал понятную причину
  }
  initializeApp({
    credential: cert({
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      // Render хранит \n как два символа: нужно превратить в реальные переводы строк
      privateKey: FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function verifyTelegramAuth(queryObj) {
  const { hash, ...data } = queryObj;
  // сортируем по ключам и собираем "k=v" через \n
  const dataCheckString = Object.keys(data)
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join('\n');

  const secretKey = crypto
    .createHash('sha256')
    .update(TG_BOT_TOKEN)
    .digest();

  const hmac = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest('hex');

  return hmac === hash;
}

app.get('/tg/callback', async (req, res) => {
  try {
    if (!TG_BOT_TOKEN) return res.status(500).send('TG_BOT_TOKEN not configured');

    if (!verifyTelegramAuth(req.query)) {
      return res.status(403).send('Invalid Telegram hash');
    }

    const {
      id,
      first_name,
      last_name,
      username,
      photo_url,
      auth_date,
      phone = '', // если ты прокидываешь ?phone=... со страницы хостинга
    } = req.query;

    const uid = `tg_${id}`;

    const claims = {
      tgId: String(id),
      username: username || '',
      phone: phone || '',
      name: [first_name, last_name].filter(Boolean).join(' '),
      authProvider: 'telegram',
    };

    const customToken = await getAuth().createCustomToken(uid, claims);

    const url =
      `${APP_DEEPLINK}?token=${encodeURIComponent(customToken)}` +
      `&phone=${encodeURIComponent(phone || '')}` +
      `&name=${encodeURIComponent(claims.name)}`;

    // редирект прямо в приложение по диплинку
    return res.redirect(url);
  } catch (err) {
    console.error('tg/callback error:', err);
    return res.status(500).send('Server error');
  }
});

app.get('/', (_req, res) => res.send('OK'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server started on', port));
