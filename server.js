// Telegram Login → Firebase Custom Token + умный upsert профиля по номеру
// + обновление фото из Telegram и удаление старой фотки из Firebase Storage (если она там)

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
  ANDROID_PACKAGE = 'com.zernoapp',

  FIREBASE_SERVICE_ACCOUNT_JSON,
  FIREBASE_SERVICE_ACCOUNT_B64,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  FIREBASE_STORAGE_BUCKET,

  DEBUG_ALLOW_BYPASS = '0',
} = process.env;

// ---- Firebase Admin init ----
function buildServiceAccount() {
  if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    return JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
  }
  if (FIREBASE_SERVICE_ACCOUNT_B64) {
    return JSON.parse(Buffer.from(FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8'));
  }
  if (FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY) {
    return {
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    };
  }
  throw new Error('No Firebase service account provided');
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

let adminInited = false;
try {
  if (!getApps().length) {
    const svc = buildServiceAccount();
    const firebaseApp = initializeApp({
      credential: cert(svc),
      storageBucket: FIREBASE_STORAGE_BUCKET || `${svc.projectId}.appspot.com`,
    });
    adminInited = true;
  }
} catch (e) {
  console.error('Firebase init error', e);
}

const db = (() => {
  try { return getFirestore(); } catch { return null; }
})();
const auth = (() => {
  try { return getAuth(); } catch { return null; }
})();
const storage = (() => {
  try { return getStorage(); } catch { return null; }
})();

// ---- helpers ----
const MAX_AGE = 5 * 60; // 5 минут
function sha256(str) { return crypto.createHash('sha256').update(str).digest(); }

function tgCheckSignature(params) {
  // https://core.telegram.org/widgets/login#checking-authorization
  const dataCheckString = Object.keys(params)
    .filter(k => k !== 'hash')
    .sort()
    .map(k => `${k}=${params[k]}`)
    .join('\n');
  const secretKey = sha256(TG_BOT_TOKEN);
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  return hmac === params.hash;
}

function normPhone(input) {
  const s = String(input || '').replace(/[^\d+]/g, '');
  if (s.startsWith('+')) return s;
  if (s.startsWith('998') && s.length === 12) return '+' + s;
  return s;
}

function buildDeepLink({ token, phone }) {
  const qp = new URLSearchParams({ token, phone }).toString();
  // intent-ссылка для Android Chrome (гарантированно вернёт в наше приложение)
  const intentUrl =
    `intent://tg-auth?${qp}#Intent;scheme=zerno;package=${ANDROID_PACKAGE};end`;
  // обычный диплинк (iOS/другие браузеры)
  const customUrl = `${APP_DEEPLINK}?${qp}`;
  return { intentUrl, customUrl };
}

async function deleteOldFirebasePhotoIfNeeded(userDoc, newUrl) {
  try {
    if (!storage || !userDoc?.photoStoragePath) return;
    if (userDoc.photoURL === newUrl) return;
    await storage.bucket().file(userDoc.photoStoragePath).delete({ ignoreNotFound: true });
  } catch (e) {
    console.warn('deleteOldFirebasePhotoIfNeeded warn:', e.message);
  }
}

// ---- routes ----
app.get('/_diag', (req, res) => {
  res.json({
    ok: true,
    firebaseAdminInitialized: adminInited,
    tgBotToken: Boolean(TG_BOT_TOKEN),
    projectId: FIREBASE_PROJECT_ID || '(from JSON)',
  });
});

// Основной callback после виджета Telegram
app.get('/callback', async (req, res) => {
  try {
    const q = { ...req.query };
    const skipVerify = DEBUG_ALLOW_BYPASS === '1' && q.skipVerify === '1';

    // базовые поля от TG
    const required = ['id', 'auth_date', 'hash'];
    for (const k of required) {
      if (!q[k]) return res.status(400).send(`Missing ${k}`);
    }

    if (!skipVerify) {
      // 1) age
      const now = Math.floor(Date.now() / 1000);
      const age = Math.abs(now - Number(q.auth_date));
      if (age > MAX_AGE) return res.status(400).send('Auth data expired');

      // 2) signature
      if (!tgCheckSignature(q)) return res.status(403).send('Bad signature');
    }

    const phone = normPhone(q.phone);
    if (!phone || !phone.startsWith('+998') || phone.length !== 13) {
      return res.status(400).send('Invalid phone');
    }

    // данные из TG
    const telegramId = String(q.id);
    const firstName = q.first_name || '';
    const lastName = q.last_name || '';
    const username = q.username || '';
    const fullName = [firstName, lastName].filter(Boolean).join(' ');
    const photoURL = q.photo_url || '';

    // upsert пользователя в Firestore
    const userRef = db.collection('users').doc(phone);
    const snap = await userRef.get();
    const nowMs = Date.now();

    if (!snap.exists) {
      await userRef.set({
        phone,
        telegramId,
        firstName,
        lastName,
        fullName,
        username,
        email: '',              // можно заполнить позже в мини-опросе
        birthday: '',           // тоже через мини-опрос
        provider: 'telegram',
        createdAt: nowMs,
        lastLoginAt: nowMs,
        p
