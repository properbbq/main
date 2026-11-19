import {
  $, el, loadSession, clearSession, openSession, loadRecords, requestSettings, saveRequest, saveIssueLink, fileSave, saveReply, waitForSave, kept,
} from './common.js?v=f0b5aec2b2fe';

const session = loadSession();

function signInAtMain() {
  const folder = location.pathname.split('/').slice(-2, -1)[0];
  location.replace(`../index.html?next=${encodeURIComponent(folder)}`);
}

function notice(tone, ...content) {
  const box = el('div', { class: `notice notice-${tone}` }, el('div', { class: 'notice-text' }, ...content));
  $('#notices').append(box);
  return box;
}

const SVG = 'http://www.w3.org/2000/svg';
function build(node, inSvg = false) {
  if (typeof node === 'string') return document.createTextNode(node);
  const [tag, attributes, ...children] = node;
  const svg = inSvg || tag === 'svg';
  const element = svg ? document.createElementNS(SVG, tag) : document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
  for (const child of children) element.append(build(child, svg));
  return element;
}

async function runModules(modules, entry) {
  const urls = new Map();
  const loading = new Set();
  const load = (name) => {
    if (urls.has(name)) return urls.get(name);
    if (loading.has(name) || !Object.hasOwn(modules, name)) throw new Error(`the app is incomplete (${name})`);
    loading.add(name);
    const code = modules[name].replace(/from '\.\/([\w-]+\.js)'/g, (match, dependency) => `from '${load(dependency)}'`);
    const url = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
    urls.set(name, url);
    return url;
  };
  await import(load(entry));
}

async function start() {
  let opened;
  try {
    opened = await openSession(session);
  } catch (error) {
    if (error.code === 'signin') {
      clearSession();
      signInAtMain();
      return;
    }
    $('#app').replaceChildren(el('div', { class: 'page' }, el('div', { class: 'notice notice-error' },
      el('div', { class: 'notice-text' }, error.message),
      el('button', { class: 'btn btn-sm', type: 'button', onclick: () => location.reload() }, 'Try again'))));
    return;
  }
  const { profile, app, data } = opened;
  $('#user-name').textContent = profile.name;
  $('#user').hidden = false;
  if (app.title) {
    document.title = app.title;
    $('#brand-name').textContent = app.title;
  }
  globalThis.hiaHost = {
    template: app.template,
    profile: { username: profile.username, name: profile.name },
    data,
    refresh: async () => (await loadRecords(profile)) || data,
    async save(changes, base) {
      const requests = requestSettings(profile);
      const { id, token } = await saveRequest(requests, profile.username, changes, base);
      const link = saveIssueLink(requests, token);
      if (profile.saveToken) {
        try {
          const issue = await fileSave(requests, token, profile.saveToken);
          return { id, ...link, submitted: true, issue };
        } catch (error) {
          return { id, ...link, submitted: false, problem: error.message };
        }
      }
      return { id, ...link, submitted: false };
    },
    async checkSave(issue) {
      if (!profile.saveToken || !issue) return null;
      return saveReply(requestSettings(profile), issue, profile.saveToken);
    },
    waitForSave,
    kept: {
      load: () => kept.load(profile),
      save: (value) => kept.save(profile, value),
      clear: () => kept.clear(),
    },
  };
  $('#app').replaceChildren(build(app.markup));
  try {
    await runModules(app.modules, app.entry);
  } catch (error) {
    notice('error', `The app couldn’t start (${error.message}). Try reloading the page.`);
  }
}

if (!session) signInAtMain();
else start();
