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
const RECORDS_URL = 'data/records.enc.json';
const MAX_LINK = 7500;
const KEYS = { session: 'fbt.session.v1', local: 'fbt.local.v1' };
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
      return true;
    } catch {
      return false;
    }
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

async function deflate(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function sealForAction(requests, bytes, prefix, info, aad) {
  const actionKey = await crypto.subtle.importKey('raw', b64urlToBytes(requests.key), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const oneOff = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: actionKey }, oneOff.privateKey, 256);
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', oneOff.publicKey));
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const key = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: point, info: utf8.encode(info) }, hkdf, 256));
  return `${prefix}.${bytesToB64url(point)}.${await seal(key, bytes, aad)}`;
}

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
  return (users || await usersFile()).users?.[await sha256Hex(`fbt-user:${normalizeUsername(username)}`)] || null;
}

export const SIGN_IN_AGAIN = {
  again: 'Please sign in again.',
  changed: 'Your sign-in has changed. Please sign in again.',
};
const signInAgain = (reason = 'again') => Object.assign(new AppError('signin', SIGN_IN_AGAIN[reason]), { reason });

function checkBrowser() {
  if (!globalThis.crypto?.subtle || typeof CompressionStream === 'undefined') {
    throw new AppError('browser', 'This browser can’t open the website. Please use an up-to-date Chrome, Edge, Safari or Firefox.');
  }
}

export async function loadRecords(profile) {
  const blob = await fetchJSON(RECORDS_URL, 'records');
  if (blob.epoch !== profile.epoch) return null;
  const records = await unsealJSON(b64ToBytes(profile.dataKey), blob.data, `fbt-records|${blob.epoch}`);
  return { records, rev: blob.rev, applied: Array.isArray(blob.applied) ? blob.applied : [] };
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
      profile = await unsealJSON(b64ToBytes(session.uk), entry.profile, `fbt-profile|${session.username}`);
    } catch {
      throw signInAgain('changed');
    }
    const blob = await fetchJSON(APP_URL, 'app');
    const data = blob.epoch === profile.epoch ? await loadRecords(profile) : null;
    if (blob.epoch === profile.epoch && data) {
      const app = await unsealJSON(b64ToBytes(profile.appKey), blob.data, `fbt-app|${blob.epoch}`);
      return { profile, app, data };
    }
    if (attempt >= 8) throw new AppError('updating', 'The website is being updated. Please try again in a minute.');
    await sleep(4000);
  }
}

export async function saveRequest(requests, username, changes, base) {
  checkBrowser();
  const id = bytesToB64url(crypto.getRandomValues(new Uint8Array(12)));
  const body = { v: 1, u: normalizeUsername(username), id, t: Date.now(), base, changes };
  const packed = await deflate(utf8.encode(JSON.stringify(body)));
  const token = await sealForAction(requests, packed, 'FBT1', 'fbt/save', 'fbt-save|v1');
  return { id, token };
}

const SAVE_TEXT = 'Changes to the website’s records, sealed so only the website’s Action can open them. '
  + 'Submit this issue to confirm it’s you: the Action then saves them and closes the issue.';

export function saveIssueLink(requests, token) {
  const block = `\`\`\`fbt\n${token}\n\`\`\`\n`;
  const query = new URLSearchParams({ title: 'Save to the website', body: `<!-- fbt:save:v1 -->\n${SAVE_TEXT}\n\n${block}` });
  const link = `https://github.com/${requests.repo}/issues/new?${query}`;
  if (link.length <= MAX_LINK) return { link, fits: true, block };
  const short = new URLSearchParams({
    title: 'Save to the website',
    body: `<!-- fbt:save:v1 -->\n${SAVE_TEXT}\n\nPaste the save here (it’s been copied), replacing this line.\n`,
  });
  return { link: `https://github.com/${requests.repo}/issues/new?${short}`, fits: false, block };
}

export async function waitForSave(id, minutes = 30, stop = () => false) {
  const deadline = Date.now() + minutes * 60 * 1000;
  while (Date.now() < deadline && !stop()) {
    await sleep(5000);
    try {
      const blob = await fetchJSON(RECORDS_URL, 'records');
      if (Array.isArray(blob.applied) && blob.applied.includes(id)) return true;
    } catch { /* try again */ }
  }
  return false;
}

export const kept = {
  async load(profile) {
    const box = store.get(KEYS.local);
    if (!box || box.u !== profile.username || box.epoch !== profile.epoch) return null;
    try {
      return await unsealJSON(b64ToBytes(profile.dataKey), box.data, `fbt-local|${profile.username}`);
    } catch {
      return null;
    }
  },
  async save(profile, value) {
    const data = await sealJSON(b64ToBytes(profile.dataKey), value, `fbt-local|${profile.username}`);
    return store.set(KEYS.local, { u: profile.username, epoch: profile.epoch, data });
  },
  clear: () => store.remove(KEYS.local),
};

export function requestSettings(profile) {
  const requests = profile?.requests;
  if (!requests || !/^[\w.-]+\/[\w.-]+$/.test(requests.repo || '') || !/^[A-Za-z0-9_-]{87}$/.test(requests.key || '')) {
    throw new AppError('no-requests', 'Saving isn’t switched on yet.');
  }
  return requests;
}
