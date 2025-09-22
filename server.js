// server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import admin from 'firebase-admin';

// ---------- Firebase Admin init ----------
function initAdmin() {
  if (admin.apps.length) return;

  const jsonFromEnv =
    process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON ||
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  const b64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

  let creds = null;
  try {
    if (jsonFromEnv) creds = JSON.parse(jsonFromEnv);
    else if (b64) creds = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  } catch (e) {
    console.error('Failed to parse service account JSON:', e.message);
  }

  if (!creds) {
    throw new Error(
      'No Firebase service account found. Provide GOOGLE_APPLICATION_CREDENTIALS_JSON or FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_BASE4'
    );
  }

  admin.initializeApp({
    credential: admin.credential.cert(creds),
  });
  console.log('Firebase Admin initialized');
}

initAdmin();

// ---------- App ----------
const app = express();

app.use(
  cors({
    origin: (_origin, cb) => cb(null, true), // можно ужесточить
  })
);
app.use(express.json({ limit: '1mb' }));

app.get('/healthz', (_req, res) => res.type('text/plain').send('ok'));

function verifyTelegramPayload(payload, botToken) {
  if (!botToken) throw new Error('TG_BOT_TOKEN is not set');

  const secret = crypto.createHash('sha256').update(botToken).digest();
  const check = Object.keys(payload)
    .filter((k) => k !== 'hash' && payload[k] !== undefined && payload[k] !== null)
    .sort()
    .map((k) => `${k}=${payload[k]}`)
    .join('\n');

  const hmac = crypto.createHmac('sha256', secret).update(check).digest('hex');
  return hmac === String(payload.hash);
}

async function handleVerify(req, res) {
  try {
    const method = req.method;
    const src = method === 'GET' ? req.query : req.body;

    const redirect = src.redirect; // zerno://tg-auth
    const state = src.state;
    const phone = src.phone;

    const data = {
      id: src.id,
      first_name: src.first_name,
      last_name: src.last_name,
      username: src.username,
      photo_url: src.photo_url,
      auth_date: src.auth_date,
      hash: src.hash,
    };

    if (!data.id || !data.hash || !data.auth_date) {
      return res.status(400).json({ error: 'Bad data' });
    }

    const ok = verifyTelegramPayload(data, process.env.TG_BOT_TOKEN);
    if (!ok) return res.status(401).json({ error: 'Bad signature' });

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - Number(data.auth_date)) > 300) {
      return res.status(401).json({ error: 'Auth data expired' });
    }

    const uid = `tg_${data.id}`;
    const customToken = await admin.auth().createCustomToken(uid, {
      tg_id: String(data.id),
      tg_username: data.username || null,
      tg_name: [data.first_name, data.last_name].filter(Boolean).join(' ') || null,
    });

    if (method === 'GET' && redirect) {
      const q = new URLSearchParams({ token: customToken });
      if (phone) q.set('phone', phone);
      if (state) q.set('state', state);
      const url = `${redirect}?${q.toString()}`;
      return res.redirect(302, url);
    }

    return res.json({ customToken });
  } catch (e) {
    console.error('verify error:', e);
    return res.status(500).json({ error: e.message });
  }
}

app.get('/auth/telegram/verify', handleVerify);
app.post('/auth/telegram/verify', handleVerify);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`up on :${PORT}`));
