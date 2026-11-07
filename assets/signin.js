// The sign-in page. Main's password opens the dashboard and signs in to every site (see common.js).

import {
  $, signIn, saveSession, loadSession, openProfile, openSite, signOutEverywhere, lastName, normalizeUsername, holdToShow,
  SIGN_IN_AGAIN,
} from './common.js';

const params = new URLSearchParams(location.search);
// A site sends people here (?next=<its folder>) when they aren't signed in to it.
const next = /^[a-z0-9]{6}$/.test(params.get('next') || '') ? params.get('next') : null;

const form = $('#signin-form');
const userInput = $('#username');
const passwordInput = $('#password');
const message = $('#message');
const button = $('#submit');

function showMessage(text, field) {
  message.textContent = text;
  message.hidden = false;
  if (field) field.focus();
}

// Signed in: sign in to every site in this browser, then go back to the site that sent you here
// (if it opened) or to the dashboard.
async function go(session) {
  const profile = await openProfile(session);
  const opened = await Promise.all(profile.sites.map((site) => openSite(site, profile, session).catch(() => false)));
  const index = profile.sites.findIndex((site) => site.id === next);
  location.replace(index >= 0 && opened[index] ? `${next}/app.html` : 'home.html');
}

if (params.has('signout')) {
  signOutEverywhere();
} else {
  const session = loadSession();
  if (session) {
    go(session).catch((error) => {
      signOutEverywhere();
      showMessage(error.code === 'signin' ? error.message : SIGN_IN_AGAIN.again);
    });
  }
}

userInput.value = lastName.get();
if (Object.hasOwn(SIGN_IN_AGAIN, params.get('why') || '')) showMessage(SIGN_IN_AGAIN[params.get('why')]);
(userInput.value ? passwordInput : userInput).focus();

const hidePassword = holdToShow($('#peek'), [passwordInput]);

// Going Back to this page restores it as it was left ("Signing in…"): put it back to normal.
window.addEventListener('pageshow', (event) => {
  if (!event.persisted) return;
  button.disabled = false;
  button.textContent = 'Sign in';
  passwordInput.value = '';
  hidePassword();
  message.hidden = true;
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.hidden = true;
  const username = normalizeUsername(userInput.value);
  if (!username) return showMessage('Enter your username.', userInput);
  if (!passwordInput.value.trim()) return showMessage('Enter your password.', passwordInput);
  button.disabled = true;
  button.textContent = 'Signing in…';
  try {
    const session = await signIn(username, passwordInput.value);
    lastName.set(session.username);
    hidePassword();
    await go(saveSession({ ...session, remember: $('#remember').checked }));
  } catch (error) {
    button.disabled = false;
    button.textContent = 'Sign in';
    showMessage(error.message, error.code === 'bad-login' ? passwordInput : null);
    if (error.code === 'bad-login') passwordInput.select();
  }
});
