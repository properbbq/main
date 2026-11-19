// Shared by main's pages: signing in, the session, and opening the sites.
//
// data/users.json holds, for each sign-in, a user key locked with the password (PBKDF2-SHA256,
// then AES-256-GCM) and a profile sealed with that key: the sites, and main's private key. Each
// site's own data/users.json holds that site's user key sealed to main's public key, so signing
// in here signs in to every site in this browser. tools/main.mjs makes main's files.

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
const SESSION_HOURS = 12;
const REMEMBER_DAYS = 30;
const KEYS = { session: 'main.session.v1', username: 'main.username' };
// Each site keeps its session as "<prefix>.session.v1", and main's matches too.
const ANY_SESSION = /\.session\.v1$/;

export const normalizeUsername = (username) => String(username || '').normalize('NFC').trim().toLowerCase();
// Passwords ignore case, spaces and dashes, as on the sites.
export const normalizePassword = (password) => String(password || '').normalize('NFC').toUpperCase().replace(/[\s-]+/g, '');

// ---------------------------------------------------------------- storage

// Storage can be blocked (a private window, say). Then nothing is remembered, and that's all.
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
};

export const lastName = {
  get: () => store.get(KEYS.username) || '',
  set: (name) => store.set(KEYS.username, name),
};

// A session lasts 12 hours, or 30 days with "Keep me signed in". It holds the user key, which
// opens the profile until the password changes. Each site's session lasts as long.
export function saveSession(session) {
  signOutEverywhere();
  const hours = session.remember ? REMEMBER_DAYS * 24 : SESSION_HOURS;
  const saved = { ...session, exp: Date.now() + hours * 3600 * 1000 };
  store.set(KEYS.session, saved, session.remember ? 'local' : 'session');
  return saved;
}

export function loadSession() {
  const session = store.get(KEYS.session, 'session') || store.get(KEYS.session, 'local');
  if (!session?.uk || !(session.exp > Date.now())) {
    if (session) signOutEverywhere();
    return null;
  }
  return session;
}

// Signing out of main signs out of every site too.
export function signOutEverywhere() {
  for (const where of ['session', 'local']) {
    try {
      const storage = where === 'session' ? sessionStorage : localStorage;
      for (const key of Object.keys(storage)) if (ANY_SESSION.test(key)) storage.removeItem(key);
    } catch {
      // nothing kept
    }
  }
}

// ------------------------------------------------------------------ crypto

const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const b64urlToBytes = (text) => b64ToBytes(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));

function bytesToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(text)));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// AES-256-GCM as "<iv>.<ciphertext>" (base64url), with associated data saying what it is and
// whose it is: the sites' format, and tools/main.mjs's.
async function unseal(keyBytes, token, aad) {
  const [iv, ct] = String(token).split('.');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlToBytes(iv), additionalData: utf8.encode(aad) }, key, b64urlToBytes(ct)));
}

const unsealJSON = async (keyBytes, token, aad) => JSON.parse(fromUtf8.decode(await unseal(keyBytes, token, aad)));

async function passwordKey(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey('raw', utf8.encode(normalizePassword(password)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(saltB64), iterations }, base, 256));
}

// A site's user key, sealed to main's public key by the site's Action:
// "m1.<one-off public key>.<iv>.<ciphertext>": ECDH on P-256, then HKDF and AES-GCM.
async function openForMain(privateJwk, token, aad) {
  const [kind, point, iv, ct] = String(token).split('.');
  if (kind !== 'm1') throw new Error('unknown seal');
  const curve = { name: 'ECDH', namedCurve: 'P-256' };
  const mine = await crypto.subtle.importKey('jwk', privateJwk, curve, false, ['deriveBits']);
  const theirs = await crypto.subtle.importKey('raw', b64urlToBytes(point), curve, false, []);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirs }, mine, 256);
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const key = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: b64urlToBytes(point), info: utf8.encode('main-handoff') }, hkdf, 256));
  return unseal(key, `${iv}.${ct}`, aad);
}

// ---------------------------------------------------------------- signing in

async function fetchJSON(url, what) {
  let response;
  try {
    response = await fetch(`${url}?t=${Date.now()}`, { cache: 'no-store' });
  } catch {
    throw new AppError('network', 'Couldn’t reach the website. Check your connection and try again.');
  }
  if (response.status === 404) throw new AppError('missing', `The ${what} hasn’t been published yet.`);
  if (!response.ok) throw new AppError('network', `Couldn’t load the ${what} (error ${response.status}).`);
  return response.json();
}

export const SIGN_IN_AGAIN = {
  again: 'Please sign in again.',
  changed: 'Your password has changed. Please sign in with the new one.',
};
const signInAgain = (reason = 'again') => Object.assign(new AppError('signin', SIGN_IN_AGAIN[reason]), { reason });
const badLogin = () => new AppError('bad-login', 'That username and password don’t match.');

async function userEntry(username) {
  const users = await fetchJSON(USERS_URL, 'sign-in list');
  return users.users?.[await sha256Hex(`main-user:${normalizeUsername(username)}`)] || null;
}

export async function signIn(username, password) {
  if (!globalThis.crypto?.subtle) {
    throw new AppError('browser', 'This browser can’t open the website. Please use an up-to-date Chrome, Edge, Safari or Firefox.');
  }
  const name = normalizeUsername(username);
  const entry = await userEntry(name);
  if (!entry?.key) throw badLogin();
  let userKey;
  try {
    userKey = await unseal(await passwordKey(password, entry.salt, entry.iterations), entry.key, `main-user-key|${name}`);
  } catch {
    throw badLogin();
  }
  return { username: name, uk: bytesToB64(userKey) };
}

/** The signed-in profile: {username, name, key, sites: [{id, prefix, name, icon, old?}]}. */
export async function openProfile(session) {
  const entry = await userEntry(session.username);
  if (!entry?.profile) throw signInAgain();
  try {
    return await unsealJSON(b64ToBytes(session.uk), entry.profile, `main-profile|${session.username}`);
  } catch {
    throw signInAgain('changed');
  }
}

// Sign in to a site in this browser: its user key, sealed to main's key in the site's own
// data/users.json, becomes the site's session, as if signed in there. False if the site isn't
// published in main yet.
export async function openSite(site, profile, session) {
  let users;
  try {
    users = await fetchJSON(`${site.id}/data/users.json`, 'site');
  } catch (error) {
    if (error.code === 'missing') return false;
    throw error;
  }
  const entry = users.users?.[await sha256Hex(`${site.prefix}-user:${session.username}`)];
  if (!entry?.main) return false;
  const userKey = await openForMain(profile.key, entry.main, `${site.prefix}-main|${session.username}`);
  const where = session.remember ? 'local' : 'session';
  return store.set(`${site.prefix}.session.v1`, { username: session.username, uk: bytesToB64(userKey), exp: session.exp }, where);
}

// Holding the eye down shows what's been typed in the password box; letting go hides it.
export function holdToShow(button, inputs) {
  const set = (show) => {
    for (const input of inputs) input.type = show ? 'text' : 'password';
    button.classList.toggle('showing', show);
  };
  const hide = () => set(false);
  button.addEventListener('pointerdown', (event) => {
    event.preventDefault();
    set(true);
  });
  for (const type of ['pointerup', 'pointerleave', 'pointercancel', 'blur', 'keyup']) button.addEventListener(type, hide);
  button.addEventListener('keydown', (event) => {
    if (event.key !== ' ' && event.key !== 'Enter') return;
    event.preventDefault();
    set(true);
  });
  return hide;
}
