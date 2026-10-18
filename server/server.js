/**
 * Telegramga o'xshash chat — backend (v3: login/parol + admin panel).
 * Faqat Node.js (>=18) o'rnatilgan modullari ishlatiladi.
 *
 * Ishga tushirish:
 *   ADMIN_PASSWORD='kuchli-parol' npm start
 *
 * Muhit o'zgaruvchilari:
 *   PORT            — port (standart: 8000)
 *   ADMIN_PASSWORD  — birinchi admin paroli (admin hali yo'q bo'lganda ishlatiladi)
 *   DATA_FILE       — ma'lumotlar fayli (standart: data/db.json)
 *   SECURE_COOKIE=1 — HTTPS orqali ishlatganda yoqing
 *
 * Admin paneli: http://localhost:8000/admin
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---------- Konfiguratsiya ----------
const PORT = Number(process.env.PORT) || 8000;
const SECURE_COOKIE = process.env.SECURE_COOKIE === "1";
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "..", "data", "db.json");
const PUBLIC_DIR = path.join(__dirname, "..", "public");

const SESSION_TTL_MS = 30 * 24 * 3600 * 1000;
const MAX_TEXT = 4000;
const MAX_BODY = 1.5 * 1024 * 1024;
const MAX_PHOTO_LEN = 600 * 1024;
const HISTORY_LIMIT = 500;
const MIN_PASSWORD = 6;
const USERNAME_RE = /^[a-z][a-z0-9_]{4,31}$/;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

// ---------- Ma'lumotlar bazasi ----------
// db.users:    id -> { id, username, name, passwordHash, role: "user"|"admin", photo, blocked, createdAt }
// db.chats:    id -> { id, userIds: [a, b], createdAt, messages: [{ id, from, text, ts }] }
// db.sessions: sha256(token) -> { userId, exp }
let db = { users: {}, chats: {}, sessions: {} };

function loadDb() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    db = { users: parsed.users || {}, chats: parsed.chats || {}, sessions: parsed.sessions || {} };
    const now = Date.now();
    for (const k of Object.keys(db.sessions)) if (db.sessions[k].exp < now) delete db.sessions[k];
  } catch (e) {
    console.error("db.json o'qib bo'lmadi, zaxira nusxa olinmoqda:", e.message);
    try { fs.copyFileSync(DATA_FILE, DATA_FILE + ".broken-" + Date.now()); } catch (_) {}
  }
}

let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => writeDbNow(), 200);
}
function writeDbNow() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    const tmp = DATA_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DATA_FILE);
  } catch (e) {
    console.error("Saqlashda xato:", e);
  }
}

// ---------- Parol xeshlash (scrypt, o'rnatilgan) ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64);
  return salt.toString("hex") + ":" + hash.toString("hex");
}
function verifyPassword(pw, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [s, h] = stored.split(":");
  const test = crypto.scryptSync(pw, Buffer.from(s, "hex"), 64);
  const want = Buffer.from(h, "hex");
  return want.length === test.length && crypto.timingSafeEqual(test, want);
}

// Login urinishlari cheklovi: 15 daqiqada 10 ta xato
const failures = new Map(); // username -> { n, until }
function loginBlocked(key) {
  const f = failures.get(key);
  return !!(f && f.until > Date.now() && f.n >= 10);
}
function recordLoginFail(key) {
  const f = failures.get(key) || { n: 0, until: 0 };
  if (f.until <= Date.now()) { f.n = 0; f.until = Date.now() + 15 * 60 * 1000; }
  f.n++;
  failures.set(key, f);
}

// ---------- Yordamchilar ----------
function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }

function json(res, status, obj) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(obj));
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", c => {
      size += c.length;
      if (size > MAX_BODY) { reject(httpError(413, "So'rov juda katta")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(httpError(400, "Noto'g'ri JSON")); }
    });
    req.on("error", reject);
  });
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach(part => {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function setSessionCookie(res, token, maxAgeSec) {
  const parts = [`sid=${encodeURIComponent(token)}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAgeSec}`];
  if (SECURE_COOKIE) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function currentUser(req) {
  const token = parseCookies(req).sid;
  if (!token) return null;
  const s = db.sessions[sha256(token)];
  if (!s || s.exp < Date.now()) return null;
  const u = db.users[s.userId];
  if (!u || u.blocked) return null;
  return u;
}

function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  db.sessions[sha256(token)] = { userId, exp: Date.now() + SESSION_TTL_MS };
  persist();
  setSessionCookie(res, token, Math.floor(SESSION_TTL_MS / 1000));
}

function destroySessionsOf(userId) {
  for (const k of Object.keys(db.sessions)) if (db.sessions[k].userId === userId) delete db.sessions[k];
}

function selfView(u) {
  return { id: u.id, username: u.username, name: u.name || "", photo: u.photo || null, role: u.role };
}
function publicView(u) {
  return { id: u.id, name: u.name || "", username: u.username || "", photo: u.photo || null };
}

function validUsername(u) { return USERNAME_RE.test(u); }
function usernameTaken(u, exceptId) {
  return Object.values(db.users).some(x => x.username === u && x.id !== exceptId);
}

function notify(userIds, payload) {
  const line = `data: ${JSON.stringify(payload)}\n\n`;
  for (const uid of userIds) {
    const set = sseClients.get(uid);
    if (set) for (const res of set) res.write(line);
  }
}

// ---------- Real vaqt (SSE) ----------
const sseClients = new Map(); // userId -> Set<res>

function openEventStream(req, res, user) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write(": connected\n\n");
  if (!sseClients.has(user.id)) sseClients.set(user.id, new Set());
  sseClients.get(user.id).add(res);
  const hb = setInterval(() => res.write(": ping\n\n"), 25000);
  req.on("close", () => {
    clearInterval(hb);
    const set = sseClients.get(user.id);
    if (set) { set.delete(res); if (!set.size) sseClients.delete(user.id); }
  });
}

// ---------- Chat yordamchilari ----------
function chatForUser(user, chatId) {
  const c = db.chats[chatId];
  return c && c.userIds.includes(user.id) ? c : null;
}
function partnerOf(chat, userId) {
  return db.users[chat.userIds.find(x => x !== userId)] || null;
}

// ---------- Admin ----------
function ensureAdmin() {
  if (Object.values(db.users).some(u => u.role === "admin")) return;
  let username = "admin";
  if (usernameTaken(username)) username = "admin" + crypto.randomBytes(2).toString("hex");
  const pwd = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString("base64url");
  const id = crypto.randomUUID();
  db.users[id] = {
    id, username, name: "Admin", passwordHash: hashPassword(pwd),
    role: "admin", photo: null, blocked: false, createdAt: Date.now(),
  };
  persist();
  console.log(`Admin yaratildi: login="${username}"`);
  if (!process.env.ADMIN_PASSWORD) console.log(`Admin paroli (saqlab qo'ying): ${pwd}`);
}

function adminStats() {
  const msgs = Object.values(db.chats).reduce((n, c) => n + c.messages.length, 0);
  return {
    users: Object.keys(db.users).length,
    blocked: Object.values(db.users).filter(u => u.blocked).length,
    chats: Object.keys(db.chats).length,
    messages: msgs,
  };
}

async function handleAdmin(req, res, pathname, admin) {
  const method = req.method;

  if (method === "GET" && pathname === "/api/admin/stats") {
    return json(res, 200, adminStats());
  }

  if (method === "GET" && pathname === "/api/admin/users") {
    const list = Object.values(db.users)
      .map(u => ({
        id: u.id, username: u.username, name: u.name || "", photo: u.photo || null,
        role: u.role, blocked: !!u.blocked, createdAt: u.createdAt,
        chatCount: Object.values(db.chats).filter(c => c.userIds.includes(u.id)).length,
      }))
      .sort((a, b) => a.createdAt - b.createdAt);
    return json(res, 200, { users: list });
  }

  if (method === "POST" && pathname === "/api/admin/users") {
    const body = await readBody(req);
    const username = String(body.username || "").trim().toLowerCase();
    const name = String(body.name || "").trim() || username;
    const password = String(body.password || "");
    if (!validUsername(username)) return json(res, 400, { error: "Login noto'g'ri: harf bilan boshlansin, 5–32 belgi, a–z, 0–9, _" });
    if (name.length > 40) return json(res, 400, { error: "Ism 40 belgidan oshmasin" });
    if (password.length < MIN_PASSWORD) return json(res, 400, { error: `Parol kamida ${MIN_PASSWORD} belgi bo'lsin` });
    if (usernameTaken(username)) return json(res, 409, { error: "Bu login band" });
    const id = crypto.randomUUID();
    db.users[id] = {
      id, username, name, passwordHash: hashPassword(password),
      role: "user", photo: null, blocked: false, createdAt: Date.now(),
    };
    persist();
    return json(res, 200, { ok: true, id });
  }

  const userMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
  if (userMatch) {
    const targetId = decodeURIComponent(userMatch[1]);
    const target = db.users[targetId];
    if (!target) return json(res, 404, { error: "Foydalanuvchi topilmadi" });

    if (method === "PATCH") {
      const body = await readBody(req);
      if (body.name !== undefined) {
        const name = String(body.name).trim();
        if (!name || name.length > 40) return json(res, 400, { error: "Ism 1–40 belgi bo'lsin" });
        target.name = name;
      }
      if (body.username !== undefined) {
        const username = String(body.username).trim().toLowerCase();
        if (!validUsername(username)) return json(res, 400, { error: "Login noto'g'ri" });
        if (usernameTaken(username, target.id)) return json(res, 409, { error: "Bu login band" });
        target.username = username;
      }
      if (body.password !== undefined) {
        const password = String(body.password);
        if (password.length < MIN_PASSWORD) return json(res, 400, { error: `Parol kamida ${MIN_PASSWORD} belgi bo'lsin` });
        target.passwordHash = hashPassword(password);
        destroySessionsOf(target.id); // parol o'zgarsa, eski sessiyalar tugaydi
      }
      if (body.blocked !== undefined) {
        if (target.id === admin.id) return json(res, 400, { error: "O'zingizni bloklay olmaysiz" });
        target.blocked = !!body.blocked;
        if (target.blocked) destroySessionsOf(target.id);
      }
      persist();
      return json(res, 200, { ok: true });
    }

    if (method === "DELETE") {
      if (target.id === admin.id) return json(res, 400, { error: "O'zingizni o'chira olmaysiz" });
      destroySessionsOf(target.id);
      for (const [cid, c] of Object.entries(db.chats)) {
        if (c.userIds.includes(target.id)) {
          delete db.chats[cid];
          notify(c.userIds.filter(x => x !== target.id), { type: "chat_deleted", chatId: cid });
        }
      }
      delete db.users[target.id];
      persist();
      return json(res, 200, { ok: true });
    }
  }

  if (method === "GET" && pathname === "/api/admin/chats") {
    const list = Object.values(db.chats).map(c => {
      const last = c.messages[c.messages.length - 1] || null;
      return {
        id: c.id,
        participants: c.userIds.map(id => db.users[id]).filter(Boolean).map(publicView),
        messageCount: c.messages.length,
        lastTs: last ? last.ts : c.createdAt,
        createdAt: c.createdAt,
      };
    }).sort((a, b) => b.lastTs - a.lastTs);
    return json(res, 200, { chats: list });
  }

  const chatMatch = pathname.match(/^\/api\/admin\/chats\/([^/]+)$/);
  if (chatMatch) {
    const chat = db.chats[decodeURIComponent(chatMatch[1])];
    if (!chat) return json(res, 404, { error: "Chat topilmadi" });

    if (method === "GET") {
      const name = id => (db.users[id] ? (db.users[id].name || db.users[id].username) : "(o'chirilgan)");
      return json(res, 200, {
        chat: { id: chat.id, participants: chat.userIds.map(id => db.users[id]).filter(Boolean).map(publicView) },
        messages: chat.messages.slice(-1000).map(m => ({ id: m.id, from: m.from, fromName: name(m.from), text: m.text, ts: m.ts })),
      });
    }

    if (method === "DELETE") {
      delete db.chats[chat.id];
      persist();
      notify(chat.userIds, { type: "chat_deleted", chatId: chat.id });
      return json(res, 200, { ok: true });
    }
  }

  return json(res, 404, { error: "Topilmadi" });
}

// ---------- API ----------
async function handleApi(req, res, pathname) {
  const method = req.method;

  // Login / logout (login talab qilmaydi)
  if (method === "POST" && pathname === "/api/auth/login") {
    const body = await readBody(req);
    const username = String(body.username || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!username || !password) return json(res, 400, { error: "Login va parolni kiriting" });
    if (loginBlocked(username)) return json(res, 429, { error: "Juda ko'p urinish. 15 daqiqadan keyin qayta urining" });

    const user = Object.values(db.users).find(u => u.username === username);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      recordLoginFail(username);
      return json(res, 401, { error: "Login yoki parol noto'g'ri" });
    }
    if (user.blocked) return json(res, 403, { error: "Hisobingiz bloklangan. Admin bilan bog'laning" });
    failures.delete(username);
    createSession(res, user.id);
    return json(res, 200, { user: selfView(user) });
  }

  if (method === "POST" && pathname === "/api/auth/logout") {
    const token = parseCookies(req).sid;
    if (token) { delete db.sessions[sha256(token)]; persist(); }
    setSessionCookie(res, "", 0);
    return json(res, 200, { ok: true });
  }

  // Bundan keyingi yo'llar uchun login kerak
  const user = currentUser(req);
  if (!user) return json(res, 401, { error: "Kirish talab qilinadi" });

  if (method === "GET" && pathname === "/api/events") {
    return openEventStream(req, res, user);
  }

  if (pathname.startsWith("/api/admin/")) {
    if (user.role !== "admin") return json(res, 403, { error: "Ruxsat yo'q" });
    return handleAdmin(req, res, pathname, user);
  }

  // Men
  if (method === "GET" && pathname === "/api/me") {
    return json(res, 200, { user: selfView(user) });
  }

  if (method === "PUT" && pathname === "/api/me") {
    const body = await readBody(req);
    const name = String(body.name ?? user.name ?? "").trim();
    const username = String(body.username ?? user.username ?? "").trim().toLowerCase();
    if (!name || name.length > 40) return json(res, 400, { error: "Ism 1–40 belgi bo'lishi kerak" });
    if (!validUsername(username)) return json(res, 400, { error: "Username noto'g'ri" });
    if (usernameTaken(username, user.id)) return json(res, 409, { error: "Bu username band" });

    if ("photo" in body) {
      if (body.photo === null) user.photo = null;
      else if (typeof body.photo === "string" && body.photo.startsWith("data:image/") && body.photo.length <= MAX_PHOTO_LEN) {
        user.photo = body.photo;
      } else return json(res, 400, { error: "Rasm noto'g'ri yoki juda katta" });
    }

    if (body.newPassword) {
      const newPassword = String(body.newPassword);
      if (!verifyPassword(String(body.currentPassword || ""), user.passwordHash)) {
        return json(res, 400, { error: "Joriy parol noto'g'ri" });
      }
      if (newPassword.length < MIN_PASSWORD) return json(res, 400, { error: `Yangi parol kamida ${MIN_PASSWORD} belgi bo'lsin` });
      user.passwordHash = hashPassword(newPassword);
    }

    user.name = name;
    user.username = username;
    persist();

    for (const c of Object.values(db.chats)) {
      if (c.userIds.includes(user.id)) notify(c.userIds.filter(x => x !== user.id), { type: "profile" });
    }
    return json(res, 200, { user: selfView(user) });
  }

  // Chatlar ro'yxati
  if (method === "GET" && pathname === "/api/chats") {
    const list = Object.values(db.chats)
      .filter(c => c.userIds.includes(user.id))
      .map(c => {
        const partner = partnerOf(c, user.id);
        if (!partner) return null;
        const last = c.messages[c.messages.length - 1] || null;
        return {
          id: c.id,
          partner: publicView(partner),
          last: last ? { text: last.text, ts: last.ts, from: last.from } : null,
          updatedAt: last ? last.ts : c.createdAt,
        };
      })
      .filter(Boolean)
      .sort((a, b) => b.updatedAt - a.updatedAt);
    return json(res, 200, { chats: list });
  }

  // Username orqali chat ochish
  if (method === "POST" && pathname === "/api/chats") {
    const body = await readBody(req);
    const username = String(body.username || "").trim().replace(/^@/, "").toLowerCase();
    if (!username) return json(res, 400, { error: "Username kiriting" });
    const partner = Object.values(db.users).find(u => u.username === username && !u.blocked);
    if (!partner) return json(res, 404, { error: "Bunday username topilmadi" });
    if (partner.id === user.id) return json(res, 400, { error: "O'zingiz bilan chat ochib bo'lmaydi" });

    let chat = Object.values(db.chats).find(c => c.userIds.includes(user.id) && c.userIds.includes(partner.id));
    if (!chat) {
      chat = { id: crypto.randomUUID(), userIds: [user.id, partner.id], createdAt: Date.now(), messages: [] };
      db.chats[chat.id] = chat;
      persist();
      notify([partner.id], { type: "chats" });
    }
    return json(res, 200, { id: chat.id, partner: publicView(partner) });
  }

  // Chat xabarlari
  const msgMatch = pathname.match(/^\/api\/chats\/([^/]+)\/messages$/);
  if (msgMatch) {
    const chat = chatForUser(user, decodeURIComponent(msgMatch[1]));
    if (!chat) return json(res, 404, { error: "Chat topilmadi" });

    if (method === "GET") {
      return json(res, 200, {
        chat: { id: chat.id, partner: publicView(partnerOf(chat, user.id)) },
        messages: chat.messages.slice(-HISTORY_LIMIT),
      });
    }
    if (method === "POST") {
      const body = await readBody(req);
      const text = String(body.text || "").trim();
      if (!text) return json(res, 400, { error: "Xabar bo'sh" });
      if (text.length > MAX_TEXT) return json(res, 400, { error: "Xabar juda uzun" });
      const message = { id: crypto.randomUUID(), from: user.id, text, ts: Date.now() };
      chat.messages.push(message);
      persist();
      notify(chat.userIds, { type: "new_message", chatId: chat.id, message });
      return json(res, 200, { message });
    }
  }

  // Chatni o'chirish
  const chatMatch = pathname.match(/^\/api\/chats\/([^/]+)$/);
  if (chatMatch && method === "DELETE") {
    const chat = chatForUser(user, decodeURIComponent(chatMatch[1]));
    if (!chat) return json(res, 404, { error: "Chat topilmadi" });
    const members = chat.userIds.slice();
    delete db.chats[chat.id];
    persist();
    notify(members, { type: "chat_deleted", chatId: chat.id });
    return json(res, 200, { ok: true });
  }

  return json(res, 404, { error: "Topilmadi" });
}

// ---------- Statik fayllar ----------
function serveFile(res, file) {
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); return res.end("Topilmadi"); }
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    });
    res.end(buf);
  });
}

function serveStatic(res, pathname) {
  if (pathname === "/admin" || pathname === "/admin/") return serveFile(res, path.join(PUBLIC_DIR, "admin.html"));
  let rel;
  try { rel = pathname === "/" ? "/index.html" : decodeURIComponent(pathname); }
  catch { res.writeHead(400); return res.end("Bad request"); }
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end("Forbidden"); }
  serveFile(res, file);
}

// ---------- Server ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname;
  try {
    if (pathname.startsWith("/api/")) await handleApi(req, res, pathname);
    else serveStatic(res, pathname);
  } catch (e) {
    if (e.status) return json(res, e.status, { error: e.message });
    console.error("Xato:", e);
    if (!res.headersSent) json(res, 500, { error: "Serverda xato" });
  }
});

function shutdown() {
  clearTimeout(saveTimer);
  writeDbNow();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

loadDb();
ensureAdmin();
server.listen(PORT, () => {
  console.log(`Chat server: http://localhost:${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin`);
});
