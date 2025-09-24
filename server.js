// Telegram Login → Firebase Custom Token + умный upsert профиля по номеру
// + удаление старой фотки из Firebase Storage (если была)
// + авто-возврат в приложение (Android: intent://, iOS/прочее: авто-HTML)

import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage';

const {
  TG_BOT_TOKEN,
  APP_DEEPLINK = 'zerno://tg-auth',

  FIREBASE_SERVICE_ACCOUNT_JSON,
  FIREBASE_SERVICE_ACCOUNT_B64,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  FIREBASE_STORAGE_BUCKET,

  ANDROID_PACKAGE = 'com.zernoapp',
  DEBUG_ALLOW_BYPASS = '0',
} = process.env;

/* ── helpers ─────────────────────────────────────────────── */
const maskEmail = (email = '') => {
  const [u, d] = String(email).split('@');
  if (!d) return '***';
  const user = u?.length > 2 ? `${u[0]}***${u[u.length - 1]}` : '***';
  return `${user}@${d}`;
};
const maskKey = (s = '') => (String(s).length < 16 ? '***' : `${s.slice(0,10)}...${s.slice(-10)}`);

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
let defaultBucketName = FIREBASE_STORAGE_BUCKET || (creds?.projectId ? `${creds.projectId}.appspot.com` : undefined);

console.log('[env] TG_BOT_TOKEN:', TG_BOT_TOKEN ? 'SET' : 'MISSING');
console.log('[env] DEBUG_ALLOW_BYPASS:', DEBUG_ALLOW_BYPASS);
console.log('[env] ANDROID_PACKAGE:', ANDROID_PACKAGE);
if (creds) {
  console.log('[env] Firebase creds method:', creds.method);
  console.log('[env] projectId:', creds.projectId);
  console.log('[env] clientEmail:', maskEmail(creds.clientEmail));
  console.log('[env] privateKey:', maskKey(creds.privateKey));
} else {
  console.error('[env] Firebase creds: NOT FOUND');
}

/* ── init firebase-admin ─────────────────────────────────── */
if (!getApps().length && creds) {
  try {
    initializeApp({
      credential: cert({
        projectId: creds.projectId,
        clientEmail: creds.clientEmail,
        privateKey: creds.privateKey,
      }),
      storageBucket: defaultBucketName,
    });
    console.log('[firebase-admin] initializeApp: OK; bucket =', defaultBucketName || '(default)');
  } catch (e) { console.error('[firebase-admin] initializeApp FAILED:', e.message); }
}

/* ── app ─────────────────────────────────────────────────── */
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* diagnostics */
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
    ANDROID_PACKAGE,
  });
});

const BOT_TOKEN = (TG_BOT_TOKEN || '').trim();

/* Telegram verify */
const TL_ALLOWED_KEYS = new Set(['id','first_name','last_name','username','photo_url','auth_date','allow_write_to_pm']);
const tokenSecret = () => crypto.createHash('sha256').update(BOT_TOKEN).digest();

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

/* storage helper */
function parseGsFileFromUrl(url = '', bucketName) {
  if (!url) return null;
  try {
    if (url.startsWith('gs://')) {
      const u = new URL(url);
      if (bucketName && u.host !== bucketName) return null;
      return u.pathname.replace(/^\/+/, '');
    }
    if (url.includes('firebasestorage.googleapis.com')) {
      const u = new URL(url);
      const parts = u.pathname.split('/').filter(Boolean);
      const iB = parts.indexOf('b');
      const iO = parts.indexOf('o');
      if (iB >= 0 && iO >= 0 && parts[iB+1] && parts[iO+1]) {
        const b = parts[iB+1];
        if (bucketName && b !== bucketName) return null;
        return decodeURIComponent(parts[iO+1]);
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
    if (!relPath) return;
    await getStorage().bucket(bucketName).file(relPath).delete({ ignoreNotFound: true });
    console.log('[storage] deleted old photo:', relPath);
  } catch (e) {
    console.warn('[storage] delete old photo failed:', e?.message || e);
  }
}

/* алиасы старых путей */
function redirectToCallback(req, res) {
  const qs = new URLSearchParams(req.query || {}).toString();
  res.redirect(302, '/tg/callback' + (qs ? `?${qs}` : ''));
}
app.get('/auth/telegram/verify', redirectToCallback);
app.get('/auth/telegram/callback', redirectToCallback);
app.get('/tg/verify', redirectToCallback);

/* основной callback */
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
      phone = '', // ожидаем 998XXXXXXXXX (без '+')
    } = req.query;

    const phoneE164 = phone ? (phone.startsWith('+') ? phone : `+${phone}`) : '';
    if (!phoneE164) return res.status(400).send('Phone is required');

    // upsert профиля
    try {
      const db = getFirestore();
      const ref = db.doc(`users/${phoneE164}`);
      const snap = await ref.get();
      const name = [first_name, last_name].filter(Boolean).join(' ') || first_name || null;

      if (snap.exists) {
        const old = snap.data() || {};
        if (photo_url && old.photoURL && photo_url !== old.photoURL) {
          await deleteOldPhotoIfInStorage(old.photoURL);
        }
        await ref.set({
          firstName: old.firstName ?? (first_name || null),
          lastName : old.lastName  ?? (last_name  || null),
          fullName : old.fullName  ?? (name || null),
          username : old.username  ?? (username || null),
          photoURL : photo_url || old.photoURL || null,
          provider : old.provider || 'telegram',
          lastLoginAt: Date.now(),
          createdAt: old.createdAt || Date.now(),
          telegramId: String(id),
        }, { merge: true });
      } else {
        await ref.set({
          phone: phoneE164,
          firstName: first_name || null,
          lastName:  last_name  || null,
          fullName:  name       || null,
          username:  username   || null,
          photoURL:  photo_url  || null,
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
    }

    // кастом-токен
    const uid = `tg_${id}`;
    const name = [req.query.first_name, req.query.last_name].filter(Boolean).join(' ');
    const claims = { tgId: String(id), username: username || '', phone: phoneE164, name, authProvider: 'telegram' };
    const customToken = await getAuth().createCustomToken(uid, claims);

    // диплинк: ВАЖНО — phone в ссылке БЕЗ '+', чтобы в RN не получился '++998…'
    const phoneNoPlus = phoneE164.replace(/^\+/, '');
    const queryPart = `token=${encodeURIComponent(customToken)}&phone=${encodeURIComponent(phoneNoPlus)}`;
    const intentUrl = `intent://tg-auth?${queryPart}#Intent;scheme=zerno;package=${ANDROID_PACKAGE};end`;
    const deeplink  = `${APP_DEEPLINK}?${queryPart}`;

    const ua = String(req.headers['user-agent'] || '');
    if (/Android/i.test(ua) && /Chrome/i.test(ua)) {
      return res.redirect(intentUrl);
    }

    // iOS/прочее — авто-HTML
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.end(`<!doctype html>
<meta http-equiv="refresh" content="0;url=${deeplink}">
<a href="${deeplink}" style="font-family:sans-serif">Open ZernoApp</a>`);
  } catch (e) {
    console.error('tg/callback error:', e);
    return res.status(500).send('Server error');
  }
});

/* healthcheck */
app.get('/', (_req, res) => res.send('OK'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server started on', port));
