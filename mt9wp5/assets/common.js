export const $ = (selector) => document.querySelector(selector);

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key in node && !key.includes('-')) node[key] = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export class AppError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();
const USERS_URL = 'data/users.json';
const APP_URL = 'data/app.enc.json';
const KEYS = { session: 'ctjm.session.v1', rates: 'ctjm.rates.v1' };
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

export const normalizeUsername = (username) => String(username || '').normalize('NFC').trim().toLowerCase();

const store = {
  get(key, where = 'local') {
    try {
      return JSON.parse((where === 'session' ? sessionStorage : localStorage).getItem(key) || 'null');
    } catch {
      return null;
    }
  },
  set(key, value, where = 'local') {
    try {
      (where === 'session' ? sessionStorage : localStorage).setItem(key, JSON.stringify(value));
    } catch { /* not remembered */ }
  },
  remove(key, where = 'local') {
    try {
      (where === 'session' ? sessionStorage : localStorage).removeItem(key);
    } catch { /* nothing kept */ }
  },
};

export function loadSession() {
  const session = store.get(KEYS.session, 'session') || store.get(KEYS.session, 'local');
  if (!session?.uk || !(session.exp > Date.now())) {
    if (session) clearSession();
    return null;
  }
  return session;
}

export function clearSession() {
  store.remove(KEYS.session, 'session');
  store.remove(KEYS.session, 'local');
}

const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const b64urlToBytes = (text) => b64ToBytes(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));

function bytesToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
const bytesToB64url = (bytes) => bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(text)));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function seal(keyBytes, bytes, aad) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8.encode(aad) }, key, bytes));
  return `${bytesToB64url(iv)}.${bytesToB64url(ct)}`;
}

async function unseal(keyBytes, token, aad) {
  const [iv, ct] = String(token).split('.');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlToBytes(iv), additionalData: utf8.encode(aad) }, key, b64urlToBytes(ct)));
}

const sealJSON = (keyBytes, value, aad) => seal(keyBytes, utf8.encode(JSON.stringify(value)), aad);
const unsealJSON = async (keyBytes, token, aad) => JSON.parse(fromUtf8.decode(await unseal(keyBytes, token, aad)));

async function fetchJSON(url, what) {
  let response;
  try {
    response = await fetch(url, { cache: 'no-cache' });
  } catch {
    throw new AppError('network', 'Couldn’t reach the website. Check your connection and try again.');
  }
  if (response.status === 404) throw new AppError('missing', `The ${what} hasn’t been published yet.`);
  if (!response.ok) throw new AppError('network', `Couldn’t load the ${what} (error ${response.status}).`);
  return response.json();
}

const usersFile = () => fetchJSON(USERS_URL, 'sign-in list');

async function userEntry(username, users) {
  return (users || await usersFile()).users?.[await sha256Hex(`ctjm-user:${normalizeUsername(username)}`)] || null;
}

export const SIGN_IN_AGAIN = {
  again: 'Please sign in again.',
  changed: 'Your sign-in has changed. Please sign in again.',
};
const signInAgain = (reason = 'again') => Object.assign(new AppError('signin', SIGN_IN_AGAIN[reason]), { reason });

function checkBrowser() {
  if (!globalThis.crypto?.subtle) {
    throw new AppError('browser', 'This browser can’t open the website. Please use an up-to-date Chrome, Edge, Safari or Firefox.');
  }
}

function helperOf(profile) {
  const helper = profile?.helper;
  return helper && typeof helper.url === 'string' && /^(https:\/\/|http:\/\/127\.0\.0\.1:)/.test(helper.url) ? { url: helper.url } : null;
}

export async function openSession(session) {
  checkBrowser();
  if (!session?.uk) throw signInAgain();
  for (let attempt = 0; ; attempt += 1) {
    const users = await usersFile();
    const entry = await userEntry(session.username, users);
    if (!entry?.profile) throw signInAgain();
    let profile;
    try {
      profile = await unsealJSON(b64ToBytes(session.uk), entry.profile, `ctjm-profile|${session.username}`);
    } catch {
      throw signInAgain('changed');
    }
    const blob = await fetchJSON(APP_URL, 'app');
    if (blob.epoch === profile.epoch) {
      const app = await unsealJSON(b64ToBytes(profile.appKey), blob.data, `ctjm-app|${blob.epoch}`);
      return { profile, app, helper: helperOf(profile) };
    }
    if (attempt >= 8) throw new AppError('updating', 'The website is being updated. Please try again in a minute.');
    await sleep(4000);
  }
}

async function submit(helper, kind, tag, token) {
  if (!helper) throw new AppError('no-helper', 'Saving to the website isn’t switched on yet.');
  const request = {
    method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'follow',
    headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ action: 'submit', kind, tag, token }),
  };
  let response;
  try {
    response = await fetch(helper.url, request);
  } catch {
    try {
      await fetch(helper.url, { ...request, mode: 'no-cors' });
      return;
    } catch {
      throw new AppError('network', 'Couldn’t reach the website’s helper. Check your connection and try again.');
    }
  }
  let answer = null;
  try {
    answer = await response.json();
  } catch { /* not an answer from the helper */ }
  if (!answer?.ok) throw new AppError('helper', `The website’s helper couldn’t take it (${answer?.error || `error ${response.status}`}). Try again in a minute.`);
}

export async function ratesRequest(session, rates, seq = Date.now()) {
  return `CTJMQ1.${await sealJSON(b64ToBytes(session.uk), { seq, rates }, `ctjm-rates|${session.username}`)}`;
}

export async function saveRates(session, profile, helper, rates) {
  const seq = Date.now();
  const sealed = await sealJSON(b64ToBytes(session.uk), { seq, rates }, `ctjm-rates-here|${session.username}`);
  store.set(KEYS.rates, { username: session.username, sealed });
  if (!helper) return 'here';
  await submit(helper, 'rates', profile.tag, await ratesRequest(session, rates, seq));
  return 'saved';
}

export async function ratesHere(session) {
  const kept = store.get(KEYS.rates);
  if (kept?.username !== session.username) return null;
  try {
    return await unsealJSON(b64ToBytes(session.uk), kept.sealed, `ctjm-rates-here|${session.username}`);
  } catch {
    return null;
  }
}
