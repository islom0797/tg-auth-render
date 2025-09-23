// server.js — Telegram Login → Firebase Custom Token + умный upsert профиля по номеру
// + обновление фото из Telegram и удаление старой фотки из Firebase Storage (если она там)
import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage'; // ⬅️

const {
  TG_BOT_TOKEN,
  APP_DEEPLINK = 'zerno://tg-auth',

  FIREBASE_SERVICE_ACCOUNT_JSON,
  FIREBASE_SERVICE_ACCOUNT_B64,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,

  // если хочешь явно задать бакет (иначе возьмём <projectId>.appspot.com)
  FIREBASE_STORAGE_BUCKET,

  DEBUG_ALLOW_BYPASS = '0',
} = process.env;

/* ───────── helpers (маски в логах) ───────── */
const maskEmail = (email = '') => {
  const [u, d] = String(email).split('@');
  if (!d) return '***';
  const user = u?.length > 2 ? `${u[0]}***${u[u.length - 1]}` : '***';
  return `${user}@${d}`;
};
const maskKey = (s = '') => (String(s).length < 16 ? '***' : `${s.slice(0,10)}...${s.slice(-10)}`);

/* ───────── загрузка creds ───────── */
function loadFirebaseCredentials() {
  if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      const json = JSON.parse(String(FIREBASE_SERVICE_ACCOUNT_JSON).replace(/\\n/g, '\n'));
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

/* ───────── init firebase-admin ───────── */
let defaultBucketName = FIREBASE_STORAGE_BUCKET || (creds?.projectId ? `${creds.projectId}.appspot.com` : undefined);

if (!getApps().length && creds) {
  try {
    initializeApp({
      credential: cert({
        projectId: creds.projectId,
        clientEmail: creds.clientEmail,
        privateKey: creds.privateKey,
      }),
      storageBucket: defaultBucketName, // ⬅️ можно и без этого, но пусть будет
    });
    console.log('[firebase-admin] initializeApp: OK; bucket =', defaultBucketName || '(default)');
  } catch (e) { console.error('[firebase-admin] initializeApp FAILED:', e.message); }
}

/* ───────── app ───────── */
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ───────── diagnostics ───────── */
app.get('/_diag', (_req, res) => {
  res.json({
    ok: true,
    tgBotToken: !!TG_BOT_TOKEN,
    firebaseAdminInitialized: !!getApps().length,
    method: creds?.method || null,
    projectId: creds?.projectId || null,
    clientEmailMasked: creds?.clientEmail ? maskEmail(creds.clientEmail) : null,
    privateKeyMasked: creds?.privateKey ? maskKey(creds.privateKey) : null,
    storageBucket: defaultBucketName || null,
    DEBUG_ALLOW_BYPASS: DEBUG_ALLOW_BYPASS === '1',
  });
});

// какой бот у токена
const BOT_TOKEN = (TG_BOT_TOKEN || '').trim();
app.get('/whoami', async (_req, res) => {
  try {
    if (!BOT_TOKEN) return res.status(500).json({ ok:false, error:'TG_BOT_TOKEN not set' });
    const r = await fetch(`https://api.telegram.org/bot${encodeURIComponent(BOT_TOKEN)}/getMe`);
    res.json(await r.json());
  } catch (e) { res.status(500).json({ ok:false, error:String(e) }); }
});

/* ───────── Telegram verify ───────── */
const TL_ALLOWED_KEYS = new Set(['id','first_name','last_name','username','photo_url','auth_date','allow_write_to_pm']);
const tokenSecret = () => crypto.createHash('sha256').update(BOT_TOKEN).digest();

// строка подписи: только tg-ключи и только НЕпустые значения
function buildDataCheckString(q) {
  const data = {};
  for (const k of Object.keys(q)) {
    if (k === 'hash') continue;
    if (!TL_ALLOWED_KEYS.has(k)) continue;
    const v = q[k];
    if (v === undefined || v === null) continue;
    const s = String(v);
    if (s === '') continue;
    data[k] = s;
  }
  const dataCheckString = Object.keys(data).sort().map(k => `${k}=${data[k]}`).join('\n');
  return { data, dataCheckString };
}

app.get('/_debug-sig', (req, res) => {
  const { data, dataCheckString } = buildDataCheckString(req.query || {});
  const computed = crypto.createHmac('sha256', tokenSecret()).update(dataCheckString).digest('hex');
  const received = String(req.query?.hash || '').toLowerCase();
  res.json({ ok:true, usedKeys:Object.keys(data), dataCheckString, computedHmac:computed, receivedHash:received || null, equal: !!received && computed===received });
});

// алиасы старых путей
function redirectToCallback(req, res) {
  const qs = new URLSearchParams(req.query || {}).toString();
  res.redirect(302, '/tg/callback' + (qs ? `?${qs}` : ''));
}
app.get('/auth/telegram/verify', redirectToCallback);
app.get('/auth/telegram/callback', redirectToCallback);
app.get('/tg/verify', redirectToCallback);

/* ───────── verify ───────── */
function verifyTelegramAuth(q) {
  const { dataCheckString } = buildDataCheckString(q);
  const calc = crypto.createHmac('sha256', tokenSecret()).update(dataCheckString).digest('hex');
  const okHash = calc === String(q.hash || '').toLowerCase();
  if (!okHash) return { ok:false, reason:'bad-hash' };
  const now = Math.floor(Date.now()/1000);
  const ts = Number(q.auth_date || 0);
  if (!ts || now - ts > 60*60*24) return { ok:false, reason:'stale' };
  return { ok:true };
}

/* ───────── helpers: удаление старой фотки из Storage ───────── */
function parseGsFileFromUrl(url = '', bucketName) {
  // поддержим два варианта ссылок: gs://bucket/path и https://firebasestorage.googleapis.com/...
  if (!url) return null;
  try {
    if (url.startsWith('gs://')) {
      const u = new URL(url);
      if (bucketName && u.host !== bucketName) return null;
      return u.pathname.replace(/^\/+/, ''); // path/to/file.jpg
    }
    if (url.includes('firebasestorage.googleapis.com')) {
      const u = new URL(url);
      // формат: /v0/b/<bucket>/o/<path_encoded>?...
      const parts = u.pathname.split('/').filter(Boolean);
      const iB = parts.indexOf('b');
      const iO = parts.indexOf('o');
      if (iB >= 0 && iO >= 0 && parts[iB+1] && parts[iO+1]) {
        const b = parts[iB+1];
        if (bucketName && b !== bucketName) return null;
        return decodeURIComponent(parts[iO+1]); // path/to/file.jpg
      }
    }
  } catch {}
  return null;
}

async function deleteOldPhotoIfInStorage(oldUrl) {
  try {
    if (!oldUrl) return;
    const bucketName = defaultBucketName || (creds?.projectId ? `${creds.projectId}.appspot.com` : null);
    if (!bucketName) return;
    const relPath = parseGsFileFromUrl(oldUrl, bucketName);
    if (!relPath) return; // не наш бакет — ничего не удаляем
    const bucket = getStorage().bucket(bucketName);
    await bucket.file(relPath).delete({ ignoreNotFound: true });
    console.log('[storage] deleted old photo:', relPath);
  } catch (e) {
    console.warn('[storage] delete old photo failed:', e?.message || e);
  }
}

/* ───────── основной callback ───────── */
app.get('/tg/callback', async (req, res) => {
  try {
    if (!BOT_TOKEN) return res.status(500).send('TG_BOT_TOKEN not configured');
    if (!getApps().length) return res.status(500).send('Firebase Admin is not initialized. Check ENV credentials.');

    if (!(DEBUG_ALLOW_BYPASS === '1' && String(req.query?.skipVerify) === '1')) {
      const v = verifyTelegramAuth(req.query);
      if (!v.ok) return res.status(403).send(v.reason === 'stale' ? 'Auth expired' : 'Invalid Telegram hash');
    }

    const {
      id,
      first_name = '',
      last_name = '',
      username = '',
      photo_url = '',
      phone = '',     // ожидаем 998XXXXXXXXX (без '+') — приходит с твоей страницы
    } = req.query;

    // телефон обязателен для твоей схемы входа
    const phoneE164 = phone ? (phone.startsWith('+') ? phone : `+${phone}`) : '';
    if (!phoneE164) return res.status(400).send('Phone is required');

    // 1) умный upsert профиля (обновляем фото, старую из Storage удаляем)
    try {
      const db = getFirestore();
      const ref = db.doc(`users/${phoneE164}`);
      const snap = await ref.get();
      const name = [first_name, last_name].filter(Boolean).join(' ') || first_name || null;

      if (snap.exists) {
        const old = snap.data() || {};
        // если в TG пришёл новый photo_url и он отличается от старого — удалим старый из Storage (если он там)
        if (photo_url && old.photoURL && photo_url !== old.photoURL) {
          await deleteOldPhotoIfInStorage(old.photoURL);
        }

        const delta = {
          // не затираем уже заполненные поля — кроме photoURL (её обновляем всегда при наличии новой)
          firstName: old.firstName ?? (first_name || null),
          lastName : old.lastName  ?? (last_name  || null),
          fullName : old.fullName  ?? (name       || null),
          username : old.username  ?? (username   || null),

          photoURL : photo_url || old.photoURL || null, // ⬅️ обновляем
          provider : old.provider || 'telegram',
          lastLoginAt: Date.now(),
          createdAt: old.createdAt || Date.now(),
          telegramId: String(id),
        };
        await ref.set(delta, { merge: true });
      } else {
        await ref.set({
          phone: phoneE164,
          firstName: first_name || null,
          lastName: last_name || null,
          fullName: name || null,
          username: username || null,
          photoURL: photo_url || null, // новая фотка
          email: null,
          provider: 'telegram',
          googleId: null,
          createdAt: Date.now(),
          lastLoginAt: Date.now(),
          telegramId: String(id),
        }, { merge: true });
      }
    } catch (e) {
      console.error('firestore upsert error:', e?.message || e);
      // продолжаем логин даже если запись не сохранилась
    }

    // 2) выдаём кастом-токен
    const uid = `tg_${id}`;
    const name = [req.query.first_name, req.query.last_name].filter(Boolean).join(' ');
    const claims = {
      tgId: String(id),
      username: username || '',
      phone: phoneE164,
      name,
      authProvider: 'telegram',
    };
    const customToken = await getAuth().createCustomToken(uid, claims);

    // 3) диплинк в приложение
    const deeplink =
      `${APP_DEEPLINK}?token=${encodeURIComponent(customToken)}` +
      `&phone=${encodeURIComponent(phoneE164)}` +
      `&name=${encodeURIComponent(name || '')}` +
      `&username=${encodeURIComponent(username || '')}` +
      `&photo=${encodeURIComponent(photo_url || '')}`;

    if (req.query.debug === '1') {
      return res.json({ ok: true, deeplink, note: 'обычно тут 302 на deeplink' });
    }
    return res.redirect(deeplink);
  } catch (e) {
    console.error('tg/callback error:', e);
    return res.status(500).send('Server error');
  }
});

// healthcheck
app.get('/', (_req, res) => res.send('OK'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server started on', port));
