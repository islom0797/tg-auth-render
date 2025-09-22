// server.js (Node/Express @ Render)
import express from "express";
import crypto from "crypto";
import cors from "cors";
import * as admin from "firebase-admin";

const {
  TG_BOT_TOKEN,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  APP_DEEPLINK = "zerno://tg-auth", // можно переопределить env-переменной
} = process.env;

// Инициализация Firebase Admin
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey: FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    }),
  });
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function verifyTelegramAuth(query) {
  // исключаем hash
  const { hash, ...data } = query;
  // Telegram: сортируем поля по ключу, собираем "key=value" с \n
  const sorted = Object.keys(data)
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join("\n");

  // секрет = SHA256(bot_token)
  const secret = crypto
    .createHash("sha256")
    .update(TG_BOT_TOKEN)
    .digest();

  // считаем HMAC(secret, data_check_string)
  const hmac = crypto
    .createHmac("sha256", secret)
    .update(sorted)
    .digest("hex");

  return hmac === hash;
}

app.get("/tg/callback", async (req, res) => {
  try {
    if (!TG_BOT_TOKEN) {
      return res.status(500).send("TG_BOT_TOKEN not configured");
    }
    if (!verifyTelegramAuth(req.query)) {
      return res.status(403).send("Invalid Telegram hash");
    }

    // Данные от Telegram Login Widget
    const {
      id,            // Telegram user id
      first_name,
      last_name,
      username,
      photo_url,
      auth_date,
      // ВАЖНО: phone обычно НЕ приходит из Login Widget.
      // Если у тебя уже настроен сбор номера через бота — можешь прокинуть ?phone=... сюда.
      phone = "",
    } = req.query;

    // Генерируем uid для Firebase. Можно держать стабильным tg_<id>
    const uid = `tg_${id}`;

    // Кастомные клеймы (можно расширить)
    const claims = {
      tgId: String(id),
      username: username || "",
      phone: phone || "",
      name: [first_name, last_name].filter(Boolean).join(" "),
      authProvider: "telegram",
    };

    const token = await admin.auth().createCustomToken(uid, claims);

    // Диплинк в приложение
    const url =
      `${APP_DEEPLINK}?token=${encodeURIComponent(token)}` +
      `&phone=${encodeURIComponent(phone || "")}` +
      `&name=${encodeURIComponent(claims.name)}`;

    // 302 → приложение
    res.redirect(url);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error");
  }
});

app.get("/", (_req, res) => res.send("OK"));
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server started on", port));
