'use strict';

const $ = (sel) => document.querySelector(sel);

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// Safe element builder: strings become text nodes, never HTML.
function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

// Uploaded photo if there is one, otherwise a coloured initial.
function avatar(user, cls = 'avatar') {
  if (user.avatar) return h('img', { class: cls, src: user.avatar, alt: '' });
  const letter = (user.displayName || user.username || '?').trim().charAt(0).toUpperCase();
  let hue = 0;
  for (const ch of user.id) hue = (hue * 31 + ch.charCodeAt(0)) % 360;
  const el = h('div', { class: `${cls} initials` }, letter);
  el.style.background = `hsl(${hue} 50% 42%)`;
  return el;
}

function formatTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
