import express from 'express';
import crypto from 'crypto';
import admin from 'firebase-admin';

const serviceJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
if (!serviceJson) {
  console.error('Missing FIREBASE_SERVICE_ACCOUNT_JSON');
  process.exit(1);
}
const serviceAccount = JSON.parse(serviceJson);

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

function checkTelegramAuth(data, botToken) {
  const { hash, ...rest } = data;
  const secret = crypto.createHash('sha256').update(botToken).digest();
  const checkString = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('\n');
  const hmac = crypto.createHmac('sha256', secret).update(checkString).digest('hex');
  return hmac === hash;
}

const app = express();
app.use(express.json());

app.post('/auth/telegram/verify', async (req, res) => {
  try {
    const p = req.body;
    if (!p?.id || !p?.hash) return res.status(400).json({ error: 'bad_payload' });

    const botToken = process.env.BOT_TOKEN;
    if (!botToken) return res.status(500).json({ error: 'no_bot_token' });

    if (!checkTelegramAuth(p, botToken)) return res.status(401).json({ error: 'bad_signature' });

    const now = Math.floor(Date.now()/1000);
    if (Math.abs(now - Number(p.auth_date)) > 300) return res.status(401).json({ error: 'expired' });

    const uid = `telegram:${p.id}`;
    const customToken = await admin.auth().createCustomToken(uid, {
      provider: 'telegram',
      telegramId: String(p.id),
    });

    return res.json({
      customToken,
      telegramProfile: {
        telegramId: String(p.id),
        firstName: p.first_name || null,
        lastName:  p.last_name  || null,
        fullName:  [p.first_name, p.last_name].filter(Boolean).join(' ') || null,
        username:  p.username   || null,
        photoURL:  p.photo_url  || null
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'internal' });
  }
});

app.get('/', (_, res) => res.send('ok'));
app.listen(process.env.PORT || 3000, () => console.log('up'));
