// The dashboard: a tile for each site. Every site is signed in to in this browser as the page
// opens (openSite in common.js), so a tile opens its site straight away.

import { $, el, loadSession, openProfile, openSite, signOutEverywhere } from './common.js';

const session = loadSession();

function tile(site) {
  const note = el('span', { class: 'tile-note', hidden: true });
  const node = el('a', { class: 'tile', href: `${site.id}/app.html` },
    el('img', { src: site.icon, alt: '' }), el('span', { class: 'tile-name' }, site.name), note);
  // A site not yet published in main opens at its old address while that's still there.
  const unavailable = () => {
    note.hidden = false;
    if (site.old) {
      node.href = site.old;
      note.textContent = 'At its old address for now (sign in there)';
    } else {
      node.removeAttribute('href');
      node.classList.add('tile-off');
      note.textContent = 'Not available yet';
    }
  };
  return { node, unavailable };
}

async function start() {
  let profile;
  try {
    profile = await openProfile(session);
  } catch (error) {
    if (error.code === 'signin') {
      signOutEverywhere();
      location.replace(`index.html?why=${error.reason || 'again'}`);
      return;
    }
    $('#tiles').replaceChildren(el('div', { class: 'notice notice-error' },
      el('div', { class: 'notice-text' }, error.message),
      el('button', { class: 'btn btn-sm', type: 'button', onclick: () => location.reload() }, 'Try again')));
    return;
  }
  $('#user-name').textContent = profile.name || profile.username;
  $('#user').hidden = false;
  const tiles = profile.sites.map(tile);
  $('#tiles').replaceChildren(...tiles.map((t) => t.node));
  await Promise.all(profile.sites.map(async (site, i) => {
    if (!(await openSite(site, profile, session).catch(() => false))) tiles[i].unavailable();
  }));
}

if (!session) location.replace('index.html');
else start();
