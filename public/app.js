'use strict';

const state = {
  me: null,
  peer: null,        // user object of the open chat
  lastTs: 0,         // newest message timestamp seen in the open chat
  seen: new Set(),   // message ids already rendered
  chatsTimer: null,
  msgTimer: null,
};

let pendingAvatar; // undefined = unchanged, null = remove, string = new data URL

// ---------------------------------------------------------------- auth

async function boot() {
  try {
    const { user } = await api('/api/me');
    showApp(user);
  } catch {
    showLogin();
  }
}

function showLogin() {
  $('#app').classList.add('hidden');
  $('#auth').classList.remove('hidden');
}

function showApp(user) {
  state.me = user;
  $('#auth').classList.add('hidden');
  $('#app').classList.remove('hidden');
  renderMe();
  loadChats();
  clearInterval(state.chatsTimer);
  state.chatsTimer = setInterval(loadChats, 4000);
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  $('#login-error').textContent = '';
  try {
    const { user } = await api('/api/login', {
      method: 'POST',
      body: { username: f.username.value, password: f.password.value },
    });
    f.reset();
    showApp(user);
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

$('#logout-btn').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' }).catch(() => {});
  clearInterval(state.chatsTimer);
  clearInterval(state.msgTimer);
  Object.assign(state, { me: null, peer: null, lastTs: 0, seen: new Set() });
  $('#chat').classList.add('hidden');
  $('#empty').classList.remove('hidden');
  $('#messages').replaceChildren();
  $('#chat-list').replaceChildren();
  showLogin();
});

function renderMe() {
  $('#me-btn').replaceChildren(avatar(state.me));
  $('#admin-link').classList.toggle('hidden', state.me.role !== 'admin');
}

// ---------------------------------------------------------------- chat list & search

async function loadChats() {
  let data;
  try {
    data = await api('/api/chats');
  } catch (err) {
    if (err.status === 401) location.reload(); // session expired
    return;
  }
  $('#chat-list').replaceChildren(...data.chats.map((c) =>
    h('li', {
      class: 'row' + (state.peer && state.peer.id === c.peer.id ? ' active' : ''),
      onclick: () => openChat(c.peer),
    },
    avatar(c.peer),
    h('div', { class: 'grow' },
      h('div', { class: 'name' }, c.peer.displayName),
      h('div', { class: 'preview muted' },
        (c.last.from === state.me.id ? 'You: ' : '') + c.last.text)))
  ));
  if (!data.chats.length) {
    $('#chat-list').append(h('li', { class: 'muted pad' }, 'No chats yet. Search for a name or @username above.'));
  }
}

let searchTimer = null;
$('#search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(runSearch, 250);
});

async function runSearch() {
  const q = $('#search').value.trim();
  const box = $('#search-results');
  if (!q) {
    box.classList.add('hidden');
    box.replaceChildren();
    return;
  }
  try {
    const { users } = await api(`/api/users?q=${encodeURIComponent(q)}`);
    const rows = users.map((u) => h('button', { class: 'row', onclick: () => openChat(u) },
      avatar(u),
      h('div', { class: 'grow' },
        h('div', { class: 'name' }, u.displayName),
        h('div', { class: 'muted' }, '@' + u.username))));
    if (!users.length) rows.push(h('div', { class: 'muted pad' }, 'No users found'));
    box.replaceChildren(...rows);
    box.classList.remove('hidden');
  } catch { /* ignore transient search errors */ }
}

// ---------------------------------------------------------------- messages

async function openChat(peer) {
  $('#search').value = '';
  $('#search-results').classList.add('hidden');
  state.peer = peer;
  state.lastTs = 0;
  state.seen = new Set();
  $('#empty').classList.add('hidden');
  $('#chat').classList.remove('hidden');
  $('#peer-avatar').replaceChildren(avatar(peer));
  $('#peer-name').textContent = peer.displayName;
  $('#peer-user').textContent = '@' + peer.username;
  $('#messages').replaceChildren();

  clearInterval(state.msgTimer);
  await pollMessages();
  state.msgTimer = setInterval(pollMessages, 2000);
  loadChats();
}

async function pollMessages() {
  const peer = state.peer;
  if (!peer) return;
  const since = state.lastTs;
  let data;
  try {
    data = await api(`/api/chats/${peer.id}/messages?since=${since}`);
  } catch { return; }
  if (state.peer !== peer) return; // user switched chats while we were waiting

  const box = $('#messages');
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  for (const m of data.messages) {
    if (state.seen.has(m.id)) continue;
    state.seen.add(m.id);
    state.lastTs = Math.max(state.lastTs, m.createdAt);
    box.append(bubble(m));
  }
  if (nearBottom || since === 0) box.scrollTop = box.scrollHeight;
}

function bubble(m) {
  const mine = m.from === state.me.id;
  return h('div', { class: 'bubble' + (mine ? ' mine' : '') },
    h('div', { class: 'text' }, m.text),
    h('div', { class: 'time muted' }, formatTime(m.createdAt)));
}

$('#composer').addEventListener('submit', async (e) => {
  e.preventDefault();
  const ta = $('#composer-text');
  const text = ta.value.trim();
  const peer = state.peer;
  if (!text || !peer) return;
  ta.value = '';
  try {
    await api(`/api/chats/${peer.id}/messages`, { method: 'POST', body: { text } });
    await pollMessages();
    loadChats();
  } catch (err) {
    ta.value = text; // keep the draft so nothing is lost
    alert(err.message);
  }
});

$('#composer-text').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    $('#composer').requestSubmit();
  }
});

// ---------------------------------------------------------------- profile editor

function showProfileError(msg) {
  $('#profile-error').textContent = msg;
}

function openProfile() {
  const f = $('#profile-form');
  f.displayName.value = state.me.displayName;
  f.username.value = state.me.username;
  f.currentPassword.value = '';
  f.newPassword.value = '';
  pendingAvatar = undefined;
  $('#avatar-preview').replaceChildren(avatar(state.me, 'avatar big'));
  showProfileError('');
  $('#profile-modal').classList.remove('hidden');
}

function closeProfile() {
  $('#profile-modal').classList.add('hidden');
}

$('#me-btn').addEventListener('click', openProfile);
$('#profile-cancel').addEventListener('click', closeProfile);

// Center-crop the picked image to a square JPEG so uploads stay small.
async function squareJpeg(file, size = 256) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.max(size / bitmap.width, size / bitmap.height);
  const w = bitmap.width * scale;
  const hgt = bitmap.height * scale;
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = size;
  canvas.getContext('2d').drawImage(bitmap, (size - w) / 2, (size - hgt) / 2, w, hgt);
  return canvas.toDataURL('image/jpeg', 0.85);
}

$('#avatar-file').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (!/^image\/(png|jpeg|webp|gif)$/.test(file.type)) {
    showProfileError('Choose a PNG, JPEG, WebP or GIF image');
    return;
  }
  try {
    pendingAvatar = await squareJpeg(file);
    $('#avatar-preview').replaceChildren(avatar({ ...state.me, avatar: pendingAvatar }, 'avatar big'));
    showProfileError('');
  } catch {
    showProfileError('Could not read that image');
  }
});

$('#avatar-remove').addEventListener('click', () => {
  pendingAvatar = null;
  $('#avatar-preview').replaceChildren(avatar({ ...state.me, avatar: null }, 'avatar big'));
});

$('#profile-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = { displayName: f.displayName.value, username: f.username.value };
  if (pendingAvatar !== undefined) body.avatar = pendingAvatar;
  if (f.newPassword.value) {
    body.currentPassword = f.currentPassword.value;
    body.newPassword = f.newPassword.value;
  }
  try {
    const { user } = await api('/api/me', { method: 'PATCH', body });
    state.me = user;
    pendingAvatar = undefined;
    renderMe();
    closeProfile();
    loadChats();
  } catch (err) {
    showProfileError(err.message);
  }
});

boot();
