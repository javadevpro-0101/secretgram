# Secretgram

Telegramga o'xshash shaxsiy xabarlashuv sayti. Hisoblarni faqat administrator yaratadi.
Foydalanuvchilar kirib, ismi, username'i, profil rasmi va parolini o'zgartira oladi va bir-biriga xabar yozadi.

## Tuzilishi

- `public/` — sayt (chat sahifasi, admin panel)
- `netlify/functions/api.mjs` — API (Netlify Function)
- Ma'lumot Netlify Blobs'da saqlanadi

## Netlify'ga deploy

1. Netlify'da **Add new site → Import an existing project** orqali shu repozitoriyni ulang.
2. Production branch: `netlify-version`.
3. Build command bo'sh qoldiriladi, publish directory `public` (netlify.toml dan olinadi).
4. **Site configuration → Environment variables** bo'limida qo'shing:
   - `ADMIN_PASSWORD` — admin paroli (majburiy, kamida 8 belgi)
   - `ADMIN_USERNAME` — ixtiyoriy, standart `admin`
5. Deploy qiling. Admin panel: `https://<sayt>.netlify.app/admin`

## Mahalliy ishga tushirish

```bash
npm install
ADMIN_PASSWORD=parol12345 npx netlify-cli dev
```

## Muhim

- Xabarlar shifrlanmagan. Blobs'dagi ma'lumotga sayt egasi kira oladi.
- Login cheklovi har funksiya nusxasida alohida ishlaydi.
