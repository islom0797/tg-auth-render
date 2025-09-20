// server.js (фрагмент)
import express from 'express';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import admin from 'firebase-admin';

const app = express();
app.use(bodyParser.json());

// ... admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });

app.post('/auth/telegram/verify', async (req, res) => {
  try {
    const { redirect, state, phone } = req.query; // из tg-login.html
    const data = req.body; // payload от Telegram

    // 1) верификация Telegram-подписи
    const botToken = process.env.TG_BOT_TOKEN;
    const secret = crypto.createHash('sha256').update(botToken).digest();
    const check = Object.keys(data)
      .filter(k => k !== 'hash')
      .sort()
      .map(k => `${k}=${data[k]}`)
      .join('\n');
    const hmac = crypto.createHmac('sha256', secret).update(check).digest('hex');
    if (hmac !== String(data.hash)) {
      return res.status(401).json({ error: 'Bad signature' });
    }

    // 2) генерим Firebase custom token
    const uid = `tg_${data.id}`; // ваш mapping
    const customToken = await admin.auth().createCustomToken(uid, {
      tg_id: String(data.id),
      tg_username: data.username || null,
      tg_name: data.first_name || '',
    });

    // 3) если задан redirect (deeplink) — уходим туда
    if (redirect) {
      const url = `${redirect}?token=${encodeURIComponent(customToken)}${phone ? `&phone=${encodeURIComponent(phone)}` : ''}${state ? `&state=${encodeURIComponent(state)}` : ''}`;
      return res.redirect(302, url);
    }

    // иначе JSON (старый режим)
    res.json({ customToken });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('up'));
