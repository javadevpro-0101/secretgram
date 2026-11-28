'use strict';

let editing = null;

function notify(msg, isError = false) {
  const n = $('#notice');
  n.textContent = msg;
  n.className = 'notice ' + (isError ? 'error' : 'ok');
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => { n.textContent = ''; }, 4000);
}

function genPassword() {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = new Uint8Array(14);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join('');
}

// ---------------------------------------------------------------- auth

async function boot() {
  try {
    const { user } = await api('/api/me');
    if (user.role === 'admin') return showDash(user);
  } catch { /* not signed in */ }
  $('#login-screen').classList.remove('hidden');
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
    if (user.role !== 'admin') {
      await api('/api/logout', { method: 'POST' }).catch(() => {});
      $('#login-error').textContent = 'This account is not an administrator';
      return;
    }
    showDash(user);
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

function showDash(user) {
  $('#login-screen').classList.add('hidden');
  $('#dash').classList.remove('hidden');
  $('#admin-name').textContent = `Signed in as @${user.username}`;
  loadUsers();
}

$('#logout-btn').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' }).catch(() => {});
  location.reload();
});

// ---------------------------------------------------------------- accounts

async function loadUsers() {
  try {
    const { users } = await api('/api/admin/users');
    $('#users').replaceChildren(...users.map((u) => h('tr', { class: u.disabled ? 'disabled-row' : '' },
      h('td', {}, avatar(u, 'avatar sm')),
      h('td', {}, u.displayName),
      h('td', {}, '@' + u.username),
      h('td', {}, u.role),
      h('td', {}, u.disabled ? 'Disabled' : 'Active'),
      h('td', {}, new Date(u.createdAt).toLocaleDateString()),
      h('td', { class: 'actions' },
        h('button', { onclick: () => openEditor(u) }, 'Edit'),
        h('button', { onclick: () => setDisabled(u, !u.disabled) }, u.disabled ? 'Enable' : 'Disable'),
        h('button', { class: 'danger', onclick: () => deleteUser(u) }, 'Delete')))));
  } catch (err) {
    notify(err.message, true);
  }
}

$('#create-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  try {
    await api('/api/admin/users', {
      method: 'POST',
      body: {
        username: f.username.value,
        displayName: f.displayName.value,
        password: f.password.value,
      },
    });
    notify(`Account @${f.username.value} created. Password: ${f.password.value}`);
    f.reset();
    loadUsers();
  } catch (err) {
    notify(err.message, true);
  }
});

$('#gen-pass').addEventListener('click', () => {
  $('#create-form').password.value = genPassword();
});

function openEditor(u) {
  editing = u;
  const f = $('#edit-form');
  f.displayName.value = u.displayName;
  f.username.value = u.username;
  f.password.value = '';
  $('#edit-title').textContent = `Edit @${u.username}`;
  $('#edit-error').textContent = '';
  $('#edit-card').classList.remove('hidden');
  f.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

$('#edit-cancel').addEventListener('click', () => $('#edit-card').classList.add('hidden'));

$('#edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = { displayName: f.displayName.value, username: f.username.value };
  if (f.password.value) body.password = f.password.value;
  try {
    await api(`/api/admin/users/${editing.id}`, { method: 'PATCH', body });
    $('#edit-card').classList.add('hidden');
    notify('Saved');
    loadUsers();
  } catch (err) {
    $('#edit-error').textContent = err.message;
  }
});

async function setDisabled(u, disabled) {
  try {
    await api(`/api/admin/users/${u.id}`, { method: 'PATCH', body: { disabled } });
    notify(`@${u.username} ${disabled ? 'disabled' : 'enabled'}`);
    loadUsers();
  } catch (err) {
    notify(err.message, true);
  }
}

async function deleteUser(u) {
  if (!confirm(`Delete @${u.username} and all of their messages? This cannot be undone.`)) return;
  try {
    await api(`/api/admin/users/${u.id}`, { method: 'DELETE' });
    notify(`@${u.username} deleted`);
    loadUsers();
  } catch (err) {
    notify(err.message, true);
  }
}

boot();
