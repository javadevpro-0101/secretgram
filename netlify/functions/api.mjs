/**
 * Secretgram API — Netlify Function backed by Netlify Blobs.
 *
 * Storage layout (every value is JSON):
 *   user/<id>                      user record (incl. password hash)
 *   uname/<username>               { id } — keeps usernames unique
 *   session/<sha256(token)>        { userId, expiresAt }
 *   chat/<ownerId>/<peerId>        { peerId, last } — chat list index
 *   msg/<pairKey>/<ts15>-<msgId>   one message per key (no lost updates on concurrent sends)
 *
 * Env vars (set in the Netlify dashboard):
 *   ADMIN_PASSWORD   required on first deploy, used to create the admin account
 *   ADMIN_USERNAME   optional, default "admin"
 *
 * Note: the login rate limit is kept in memory per function instance, so it is
 * best-effort: a determined attacker can reach several instances.
 */

import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 3 * 1024 * 1024;
const MAX_AVATAR_BYTES = 512 * 1024;
const MAX_MESSAGE_CHARS = 4000;
const MAX_HISTORY = 300;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILS = 10;

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Cache-Control': 'no-store',
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ---------------------------------------------------------------- helpers

const newId = () => crypto.randomBytes(12).toString('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const pairKey = (a, b) => [a, b].sort().join('_');
const tsKey = (ms) => String(ms).padStart(15, '0');

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
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
  if (!USERNAME_RE.test(u)) throw new HttpError(400, 'Username must be 3–32 characters: letters, digits or underscore');
  return u;
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

const publicView = (u) => ({ id: u.id, username: u.username, displayName: u.displayName, avatar: u.avatar });
const selfView = (u) => ({ ...publicView(u), role: u.role });
const adminView = (u) => ({ ...selfView(u), disabled: u.disabled, createdAt: u.createdAt });

// ---------------------------------------------------------------- app factory

/**
 * @param {() => object} openStore  returns a Netlify Blobs store (or a compatible fake in tests)
 */
export function createApi(openStore) {
  let store = null;
  let adminReady = false;
  let lastMessageTs = 0; // keeps message keys strictly ordered within this instance
  const loginFails = new Map(); // in-memory, per instance

  const getJSON = async (key) => (await store.get(key, { type: 'json' })) ?? null;
  const setJSON = (key, value) => store.setJSON(key, value);
  const del = (key) => store.delete(key);

  async function listKeys(prefix) {
    const keys = [];
    for await (const page of store.list({ prefix, paginate: true })) {
      for (const b of page.blobs) keys.push(b.key);
    }
    return keys;
  }

  async function listUsers() {
    const keys = (await listKeys('user/'));
    return (await Promise.all(keys.map(getJSON))).filter(Boolean);
  }

  const getUser = (id) => getJSON(`user/${id}`);

  async function findUserByUsername(username) {
    const ref = await getJSON(`uname/${username}`);
    return ref ? getUser(ref.id) : null;
  }

  // Creates the first admin from ADMIN_PASSWORD if none exists yet.
  async function ensureAdmin() {
    if (adminReady) return;
    const users = await listUsers();
    if (!users.some((u) => u.role === 'admin')) {
      const password = process.env.ADMIN_PASSWORD;
      if (!password) throw new HttpError(500, 'Server is not configured: set ADMIN_PASSWORD in Netlify');
      const username = cleanUsername(process.env.ADMIN_USERNAME || 'admin');
      const admin = {
        id: newId(), username, displayName: 'Admin', avatar: null, role: 'admin',
        disabled: false, passwordHash: hashPassword(password), createdAt: Date.now(),
      };
      await setJSON(`user/${admin.id}`, admin);
      await setJSON(`uname/${username}`, { id: admin.id });
    }
    adminReady = true;
  }

  async function currentUser(req) {
    const m = /(?:^|;\s*)sg_session=([A-Za-z0-9_-]+)/.exec(req.headers.get('cookie') || '');
    if (!m) return null;
    const session = await getJSON(`session/${sha256(m[1])}`);
    if (!session || session.expiresAt <= Date.now()) return null;
    const user = await getUser(session.userId);
    return user && !user.disabled ? user : null;
  }

  async function revokeSessions(userId) {
    for (const key of await listKeys('session/')) {
      const s = await getJSON(key);
      if (s && s.userId === userId) await del(key);
    }
  }

  function sessionCookie(value, maxAgeSec, secure) {
    return `sg_session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
  }

  async function readJson(req) {
    const text = await req.text();
    if (text.length > MAX_BODY_BYTES) throw new HttpError(413, 'Request is too large');
    if (!text) return {};
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw new HttpError(400, 'Invalid JSON'); }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new HttpError(400, 'Expected a JSON object');
    }
    return parsed;
  }

  // ------------------------------------------------------------ routes

  async function route(req) {
    const url = new URL(req.url);
    const p = url.pathname;
    const method = req.method;
    const secure = url.protocol === 'https:';

    // ---- public
    if (p === '/api/login' && method === 'POST') {
      const body = await readJson(req);
      const username = String(body.username ?? '').trim().toLowerCase();
      // Netlify sets this header itself, so clients cannot spoof it the way x-forwarded-for can be.
      const ip = req.headers.get('x-nf-client-connection-ip') || 'unknown';
      const key = `${ip}|${username}`;
      const now = Date.now();
      const entry = loginFails.get(key);
      if (entry && now - entry.first <= LOGIN_WINDOW_MS && entry.count >= LOGIN_MAX_FAILS) {
        throw new HttpError(429, 'Too many failed attempts. Try again in 15 minutes.');
      }

      const user = await findUserByUsername(username);
      if (!user || !verifyPassword(String(body.password ?? ''), user.passwordHash)) {
        if (!entry || now - entry.first > LOGIN_WINDOW_MS) loginFails.set(key, { count: 1, first: now });
        else entry.count += 1;
        throw new HttpError(401, 'Wrong username or password');
      }
      if (user.disabled) throw new HttpError(403, 'This account has been disabled');

      loginFails.delete(key);
      const token = crypto.randomBytes(32).toString('base64url');
      await setJSON(`session/${sha256(token)}`, { userId: user.id, expiresAt: now + SESSION_TTL_MS });
      return json({ user: selfView(user) }, 200, {
        'Set-Cookie': sessionCookie(token, SESSION_TTL_MS / 1000, secure),
      });
    }

    if (p === '/api/logout' && method === 'POST') {
      const m = /(?:^|;\s*)sg_session=([A-Za-z0-9_-]+)/.exec(req.headers.get('cookie') || '');
      if (m) await del(`session/${sha256(m[1])}`);
      return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0, secure) });
    }

    // ---- signed in only
    const user = await currentUser(req);
    if (!user) throw new HttpError(401, 'Not signed in');

    if (p === '/api/me' && method === 'GET') {
      return json({ user: selfView(user) });
    }

    if (p === '/api/me' && method === 'PATCH') {
      const body = await readJson(req);
      const changes = {};
      if ('displayName' in body) changes.displayName = cleanDisplayName(body.displayName);
      if ('avatar' in body) changes.avatar = cleanAvatar(body.avatar);
      let newUsername = null;
      if ('username' in body) {
        newUsername = cleanUsername(body.username);
        if (newUsername !== user.username) {
          const taken = await getJSON(`uname/${newUsername}`);
          if (taken && taken.id !== user.id) throw new HttpError(409, 'That username is taken');
        }
      }
      let newHash = null;
      if (body.newPassword !== undefined) {
        if (!verifyPassword(String(body.currentPassword ?? ''), user.passwordHash)) {
          throw new HttpError(403, 'Current password is wrong');
        }
        newHash = hashPassword(cleanPassword(body.newPassword));
      }

      if (newUsername && newUsername !== user.username) {
        await setJSON(`uname/${newUsername}`, { id: user.id });
        await del(`uname/${user.username}`);
        user.username = newUsername;
      }
      Object.assign(user, changes);
      if (newHash) user.passwordHash = newHash;
      await setJSON(`user/${user.id}`, user);
      return json({ user: selfView(user) });
    }

    if (p === '/api/users' && method === 'GET') {
      const q = (url.searchParams.get('q') || '').trim().toLowerCase().replace(/^@/, '');
      const users = (await listUsers())
        .filter((u) => !u.disabled && u.id !== user.id &&
          (u.username.includes(q) || u.displayName.toLowerCase().includes(q)))
        .slice(0, 20)
        .map(publicView);
      return json({ users });
    }

    if (p === '/api/chats' && method === 'GET') {
      const entries = await Promise.all((await listKeys(`chat/${user.id}/`)).map(getJSON));
      const chats = [];
      for (const e of entries) {
        if (!e) continue;
        const peer = await getUser(e.peerId);
        if (peer && !peer.disabled) chats.push({ peer: publicView(peer), last: e.last });
      }
      chats.sort((a, b) => b.last.createdAt - a.last.createdAt);
      return json({ chats });
    }

    const chatMatch = /^\/api\/chats\/([a-f0-9]+)\/messages$/.exec(p);
    if (chatMatch) {
      const peer = await getUser(chatMatch[1]);
      if (!peer) throw new HttpError(404, 'User not found');
      const prefix = `msg/${pairKey(user.id, peer.id)}/`;

      if (method === 'GET') {
        const since = Number(url.searchParams.get('since')) || 0;
        const keys = (await listKeys(prefix))
          .filter((k) => Number(k.slice(prefix.length, prefix.length + 15)) >= since)
          .slice(-MAX_HISTORY);
        const messages = (await Promise.all(keys.map(getJSON))).filter(Boolean);
        return json({ messages });
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
        const createdAt = Math.max(Date.now(), lastMessageTs + 1);
        lastMessageTs = createdAt;
        const message = { id: newId(), from: user.id, to: peer.id, text, createdAt };
        await setJSON(`${prefix}${tsKey(createdAt)}-${message.id}`, message);
        await setJSON(`chat/${user.id}/${peer.id}`, { peerId: peer.id, last: message });
        await setJSON(`chat/${peer.id}/${user.id}`, { peerId: user.id, last: message });
        return json({ message }, 201);
      }
    }

    // ---- admin only
    if (p.startsWith('/api/admin/')) {
      if (user.role !== 'admin') throw new HttpError(403, 'Admins only');

      if (p === '/api/admin/users' && method === 'GET') {
        const users = (await listUsers()).sort((a, b) => a.createdAt - b.createdAt);
        return json({ users: users.map(adminView) });
      }

      if (p === '/api/admin/users' && method === 'POST') {
        const body = await readJson(req);
        const username = cleanUsername(body.username);
        if (await getJSON(`uname/${username}`)) throw new HttpError(409, 'That username is taken');
        const newUser = {
          id: newId(), username,
          displayName: cleanDisplayName(body.displayName || username),
          avatar: null, role: 'user', disabled: false,
          passwordHash: hashPassword(cleanPassword(body.password)), createdAt: Date.now(),
        };
        await setJSON(`user/${newUser.id}`, newUser);
        await setJSON(`uname/${username}`, { id: newUser.id });
        return json({ user: adminView(newUser) }, 201);
      }

      const userMatch = /^\/api\/admin\/users\/([a-f0-9]+)$/.exec(p);
      if (userMatch) {
        const target = await getUser(userMatch[1]);
        if (!target) throw new HttpError(404, 'User not found');

        if (method === 'PATCH') {
          const body = await readJson(req);
          const changes = {};
          if ('displayName' in body) changes.displayName = cleanDisplayName(body.displayName);
          if ('avatar' in body) changes.avatar = cleanAvatar(body.avatar);
          if ('disabled' in body) {
            if (target.id === user.id && body.disabled) throw new HttpError(400, 'You cannot disable your own account');
            changes.disabled = Boolean(body.disabled);
          }
          let newUsername = null;
          if ('username' in body) {
            newUsername = cleanUsername(body.username);
            if (newUsername !== target.username) {
              const taken = await getJSON(`uname/${newUsername}`);
              if (taken && taken.id !== target.id) throw new HttpError(409, 'That username is taken');
            }
          }
          const newHash = body.password ? hashPassword(cleanPassword(body.password)) : null;

          if (newUsername && newUsername !== target.username) {
            await setJSON(`uname/${newUsername}`, { id: target.id });
            await del(`uname/${target.username}`);
            target.username = newUsername;
          }
          Object.assign(target, changes);
          if (newHash) target.passwordHash = newHash;
          await setJSON(`user/${target.id}`, target);
          // Disabling or resetting a password signs the user out everywhere.
          if (target.disabled || newHash) await revokeSessions(target.id);
          return json({ user: adminView(target) });
        }

        if (method === 'DELETE') {
          if (target.id === user.id) throw new HttpError(400, 'You cannot delete your own account');
          // Remove this user's chats, messages and the peers' index entries to them.
          for (const key of await listKeys(`chat/${target.id}/`)) {
            const entry = await getJSON(key);
            if (entry) {
              for (const mk of await listKeys(`msg/${pairKey(target.id, entry.peerId)}/`)) await del(mk);
              await del(`chat/${entry.peerId}/${target.id}`);
            }
            await del(key);
          }
          await revokeSessions(target.id);
          await del(`uname/${target.username}`);
          await del(`user/${target.id}`);
          return json({ ok: true });
        }
      }
    }

    throw new HttpError(404, 'Not found');
  }

  return async function handle(req) {
    try {
      store ??= openStore();
      await ensureAdmin();
      return await route(req);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error(err);
      return json({ error: 'Internal server error' }, 500);
    }
  };
}

// Production entry point: the Blobs store is provided by Netlify automatically.
const handler = createApi(() => getStore('secretgram'));

export default (req) => handler(req);

export const config = { path: '/api/*' };
