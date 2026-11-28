'use strict';
/**
 * Secretgram server — zero dependencies (Node 18+).
 *
 * - Accounts are created only by the admin (no public sign-up).
 * - Users sign in, edit their name / username / avatar / password, and message each other.
 * - Admin panel at /admin manages accounts.
 *
 * Env vars:
 *   PORT              default 3000
 *   DATA_FILE         default ./data/db.json
 *   ADMIN_USERNAME    default "admin" (used only when no admin exists yet)
 *   ADMIN_PASSWORD    if unset, a random one is generated and printed once at first start
 *   SECURE_COOKIES=1  set the Secure flag on the session cookie (use behind HTTPS)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SECURE_COOKIES = process.env.SECURE_COOKIES === '1';

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 3 * 1024 * 1024;
const MAX_AVATAR_BYTES = 512 * 1024;
const MAX_MESSAGE_CHARS = 4000;
const MAX_HISTORY = 300;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILS = 10;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ---------------------------------------------------------------- storage

let db = { users: [], sessions: [], messages: [] };

function loadDb() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function saveDb() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE); // atomic replace
}

const newId = () => crypto.randomBytes(12).toString('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------------------------------------------------------------- passwords

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(':');
  const expected = Buffer.from(hash || '', 'hex');
  const actual = crypto.scryptSync(password, salt || '', 64);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

// ---------------------------------------------------------------- validation

const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
const AVATAR_RE = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/]+={0,2})$/;

function cleanUsername(raw) {
  const u = String(raw ?? '').trim().replace(/^@/, '').toLowerCase();
  if (!USERNAME_RE.test(u)) {
    throw new HttpError(400, 'Username must be 3–32 characters: letters, digits or underscore');
  }
  return u;
}

function takenUsername(username, exceptId) {
  return db.users.some((u) => u.username === username && u.id !== exceptId);
}

function cleanDisplayName(raw) {
  const name = String(raw ?? '').trim();
  if (name.length < 1 || name.length > 64) throw new HttpError(400, 'Name must be 1–64 characters');
  return name;
}

function cleanPassword(raw) {
  const pw = String(raw ?? '');
  if (pw.length < 8 || pw.length > 200) throw new HttpError(400, 'Password must be 8–200 characters');
  return pw;
}

function cleanAvatar(raw) {
  if (raw === null) return null;
  const m = AVATAR_RE.exec(String(raw ?? ''));
  if (!m) throw new HttpError(400, 'Avatar must be a PNG, JPEG, WebP or GIF image');
  if (Buffer.byteLength(m[2], 'base64') > MAX_AVATAR_BYTES) throw new HttpError(400, 'Avatar is too large (max 512 KB)');
  return raw;
}

// What each audience is allowed to see of a user record.
const publicView = (u) => ({ id: u.id, username: u.username, displayName: u.displayName, avatar: u.avatar });
const selfView = (u) => ({ ...publicView(u), role: u.role });
const adminView = (u) => ({ ...selfView(u), disabled: u.disabled, createdAt: u.createdAt });

// ---------------------------------------------------------------- sessions

const COOKIE_RE = /(?:^|;\s*)sg_session=([A-Za-z0-9_-]+)/;

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.sessions = db.sessions.filter((s) => s.expiresAt > Date.now());
  db.sessions.push({ tokenHash: sha256(token), userId, expiresAt: Date.now() + SESSION_TTL_MS });
  return token;
}

function currentUser(req) {
  const m = COOKIE_RE.exec(req.headers.cookie || '');
  if (!m) return null;
  const session = db.sessions.find((s) => s.tokenHash === sha256(m[1]) && s.expiresAt > Date.now());
  if (!session) return null;
  const user = db.users.find((u) => u.id === session.userId);
  return user && !user.disabled ? user : null;
}

function sessionCookie(token, maxAgeSec) {
  return `sg_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${SECURE_COOKIES ? '; Secure' : ''}`;
}

// Simple brute-force protection: per IP + username.
const loginFails = new Map();

function loginAllowed(key) {
  const e = loginFails.get(key);
  if (!e) return true;
  if (Date.now() - e.first > LOGIN_WINDOW_MS) {
    loginFails.delete(key);
    return true;
  }
  return e.count < LOGIN_MAX_FAILS;
}

function recordLoginFail(key) {
  const e = loginFails.get(key);
  if (!e || Date.now() - e.first > LOGIN_WINDOW_MS) loginFails.set(key, { count: 1, first: Date.now() });
  else e.count += 1;
}

// ---------------------------------------------------------------- HTTP helpers

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Content-Security-Policy':
    "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; " +
    "script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
};

function sendJson(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        if (!tooLarge) reject(new HttpError(413, 'Request is too large'));
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) return;
      let parsed = {};
      if (size) {
        try {
          parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch {
          return reject(new HttpError(400, 'Invalid JSON'));
        }
      }
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return reject(new HttpError(400, 'Expected a JSON object'));
      }
      resolve(parsed);
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};
const PAGES = { '/': 'index.html', '/admin': 'admin.html' };

function serveStatic(res, pathname) {
  const rel = PAGES[pathname] || pathname.slice(1);
  const file = path.join(PUBLIC_DIR, path.normalize(rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return sendJson(res, 404, { error: 'Not found' });
  fs.readFile(file, (err, data) => {
    if (err) return sendJson(res, 404, { error: 'Not found' });
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
    });
    res.end(data);
  });
}

// ---------------------------------------------------------------- routes

async function route(req, res, url) {
  const p = url.pathname;
  const method = req.method;

  // ---- public
  if (p === '/api/login' && method === 'POST') {
    const body = await readJson(req);
    const username = String(body.username ?? '').trim().toLowerCase();
    const key = `${req.socket.remoteAddress}|${username}`;
    if (!loginAllowed(key)) throw new HttpError(429, 'Too many failed attempts. Try again in 15 minutes.');

    const user = db.users.find((u) => u.username === username);
    if (!user || !verifyPassword(String(body.password ?? ''), user.passwordHash)) {
      recordLoginFail(key);
      throw new HttpError(401, 'Wrong username or password');
    }
    if (user.disabled) throw new HttpError(403, 'This account has been disabled');

    loginFails.delete(key);
    const token = createSession(user.id);
    saveDb();
    return sendJson(res, 200, { user: selfView(user) }, {
      'Set-Cookie': sessionCookie(token, SESSION_TTL_MS / 1000),
    });
  }

  if (p === '/api/logout' && method === 'POST') {
    const m = COOKIE_RE.exec(req.headers.cookie || '');
    if (m) {
      db.sessions = db.sessions.filter((s) => s.tokenHash !== sha256(m[1]));
      saveDb();
    }
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
  }

  // ---- everything below needs a signed-in user
  const user = currentUser(req);
  if (!user) throw new HttpError(401, 'Not signed in');

  if (p === '/api/me' && method === 'GET') {
    return sendJson(res, 200, { user: selfView(user) });
  }

  if (p === '/api/me' && method === 'PATCH') {
    const body = await readJson(req);
    // Validate everything first, then apply, so a rejected request changes nothing.
    const changes = {};
    if ('displayName' in body) changes.displayName = cleanDisplayName(body.displayName);
    if ('username' in body) {
      changes.username = cleanUsername(body.username);
      if (takenUsername(changes.username, user.id)) throw new HttpError(409, 'That username is taken');
    }
    if ('avatar' in body) changes.avatar = cleanAvatar(body.avatar);
    let newHash = null;
    if (body.newPassword !== undefined) {
      if (!verifyPassword(String(body.currentPassword ?? ''), user.passwordHash)) {
        throw new HttpError(403, 'Current password is wrong');
      }
      newHash = hashPassword(cleanPassword(body.newPassword));
    }
    Object.assign(user, changes);
    if (newHash) user.passwordHash = newHash;
    saveDb();
    return sendJson(res, 200, { user: selfView(user) });
  }

  if (p === '/api/users' && method === 'GET') {
    const q = (url.searchParams.get('q') || '').trim().toLowerCase().replace(/^@/, '');
    const users = db.users
      .filter((u) => !u.disabled && u.id !== user.id &&
        (u.username.includes(q) || u.displayName.toLowerCase().includes(q)))
      .slice(0, 20)
      .map(publicView);
    return sendJson(res, 200, { users });
  }

  if (p === '/api/chats' && method === 'GET') {
    // Latest message per conversation partner.
    const lastByPeer = new Map();
    for (const m of db.messages) {
      if (m.from !== user.id && m.to !== user.id) continue;
      const peerId = m.from === user.id ? m.to : m.from;
      const cur = lastByPeer.get(peerId);
      if (!cur || m.createdAt >= cur.createdAt) lastByPeer.set(peerId, m);
    }
    const chats = [];
    for (const [peerId, last] of lastByPeer) {
      const peer = db.users.find((u) => u.id === peerId);
      if (peer) chats.push({ peer: publicView(peer), last });
    }
    chats.sort((a, b) => b.last.createdAt - a.last.createdAt);
    return sendJson(res, 200, { chats });
  }

  const chatMatch = /^\/api\/chats\/([a-f0-9]+)\/messages$/.exec(p);
  if (chatMatch) {
    const peerId = chatMatch[1];
    const peer = db.users.find((u) => u.id === peerId);
    if (!peer) throw new HttpError(404, 'User not found');

    if (method === 'GET') {
      const since = Number(url.searchParams.get('since')) || 0;
      const messages = db.messages.filter((m) =>
        ((m.from === user.id && m.to === peer.id) || (m.from === peer.id && m.to === user.id)) &&
        m.createdAt >= since);
      return sendJson(res, 200, { messages: messages.slice(-MAX_HISTORY) });
    }

    if (method === 'POST') {
      if (peer.id === user.id) throw new HttpError(400, 'You cannot message yourself');
      if (peer.disabled) throw new HttpError(403, 'This user is unavailable');
      const body = await readJson(req);
      const text = String(body.text ?? '').trim();
      if (!text) throw new HttpError(400, 'Message is empty');
      if (text.length > MAX_MESSAGE_CHARS) {
        throw new HttpError(400, `Message is longer than ${MAX_MESSAGE_CHARS} characters`);
      }
      const message = { id: newId(), from: user.id, to: peer.id, text, createdAt: Date.now() };
      db.messages.push(message);
      saveDb();
      return sendJson(res, 201, { message });
    }
  }

  // ---- admin only
  if (p.startsWith('/api/admin/')) {
    if (user.role !== 'admin') throw new HttpError(403, 'Admins only');

    if (p === '/api/admin/users' && method === 'GET') {
      return sendJson(res, 200, { users: db.users.map(adminView) });
    }

    if (p === '/api/admin/users' && method === 'POST') {
      const body = await readJson(req);
      const username = cleanUsername(body.username);
      if (takenUsername(username)) throw new HttpError(409, 'That username is taken');
      const newUser = {
        id: newId(),
        username,
        displayName: cleanDisplayName(body.displayName || username),
        avatar: null,
        role: 'user',
        disabled: false,
        passwordHash: hashPassword(cleanPassword(body.password)),
        createdAt: Date.now(),
      };
      db.users.push(newUser);
      saveDb();
      return sendJson(res, 201, { user: adminView(newUser) });
    }

    const userMatch = /^\/api\/admin\/users\/([a-f0-9]+)$/.exec(p);
    if (userMatch) {
      const target = db.users.find((u) => u.id === userMatch[1]);
      if (!target) throw new HttpError(404, 'User not found');

      if (method === 'PATCH') {
        const body = await readJson(req);
        const changes = {};
        if ('displayName' in body) changes.displayName = cleanDisplayName(body.displayName);
        if ('username' in body) {
          changes.username = cleanUsername(body.username);
          if (takenUsername(changes.username, target.id)) throw new HttpError(409, 'That username is taken');
        }
        if ('avatar' in body) changes.avatar = cleanAvatar(body.avatar);
        if ('disabled' in body) {
          if (target.id === user.id && body.disabled) {
            throw new HttpError(400, 'You cannot disable your own account');
          }
          changes.disabled = Boolean(body.disabled);
        }
        const newHash = body.password ? hashPassword(cleanPassword(body.password)) : null;

        Object.assign(target, changes);
        if (newHash) target.passwordHash = newHash;
        // Disabling or resetting a password signs the user out everywhere.
        if (target.disabled || newHash) db.sessions = db.sessions.filter((s) => s.userId !== target.id);
        saveDb();
        return sendJson(res, 200, { user: adminView(target) });
      }

      if (method === 'DELETE') {
        if (target.id === user.id) throw new HttpError(400, 'You cannot delete your own account');
        db.users = db.users.filter((u) => u.id !== target.id);
        db.sessions = db.sessions.filter((s) => s.userId !== target.id);
        db.messages = db.messages.filter((m) => m.from !== target.id && m.to !== target.id);
        saveDb();
        return sendJson(res, 200, { ok: true });
      }
    }
  }

  throw new HttpError(404, 'Not found');
}

// ---------------------------------------------------------------- startup

function ensureAdmin() {
  if (db.users.some((u) => u.role === 'admin')) return;
  const username = cleanUsername(process.env.ADMIN_USERNAME || 'admin');
  const generated = !process.env.ADMIN_PASSWORD;
  const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  db.users.push({
    id: newId(),
    username,
    displayName: 'Admin',
    avatar: null,
    role: 'admin',
    disabled: false,
    passwordHash: hashPassword(password),
    createdAt: Date.now(),
  });
  saveDb();
  console.log(`Created admin account "${username}"` + (generated ? ` with password: ${password}` : ''));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) {
      await route(req, res, url);
    } else if (req.method === 'GET' || req.method === 'HEAD') {
      serveStatic(res, url.pathname);
    } else {
      sendJson(res, 405, { error: 'Method not allowed' });
    }
  } catch (err) {
    if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message });
    console.error(err);
    sendJson(res, 500, { error: 'Internal server error' });
  }
});

loadDb();
ensureAdmin();
server.listen(PORT, () => console.log(`Secretgram running at http://localhost:${PORT}  (admin: /admin)`));
