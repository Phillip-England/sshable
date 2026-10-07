const $ = (id) => document.getElementById(id);
const state = { token: '', hosts: [], selected: '', view: 'overview', session: null, marks: {} };
const safe = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const mark = (name, step) => !!state.marks[name]?.[step];
const host = () => state.hosts.find(h => h.name === state.selected);
let shellTerm = null;
let shellFit = null;
let shellOffset = 0;
let shellInputQueue = Promise.resolve();
let shellResizeObserver = null;
let shellResizeSize = '';
let shellFontSize = 17;
let shellVisible = false;
let shellSelectedText = '';

async function api(path, options = {}) {
  const response = await fetch(path, {cache: 'no-store', ...options});
  if (!response.ok) throw new Error((await response.text()).trim());
  return response.json();
}
async function post(path, body) {
  return api(path, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Sshable-Token': state.token}, body: JSON.stringify(body)});
}
function toast(message) {
  const el = $('toast'); el.textContent = message; el.classList.remove('hidden');
  clearTimeout(toast.timer); toast.timer = setTimeout(() => el.classList.add('hidden'), 5500);
}
async function reload() {
  const data = await api('/api/state');
  state.token = data.token; state.hosts = data.hosts;
  if (state.selected && !host()) { state.selected = ''; state.view = 'overview'; }
  render();
}
function choose(name) { state.selected = name; state.view = 'host'; render(); }
function renderSidebar() {
  $('host-list').innerHTML = state.hosts.length ? state.hosts.map(h => `<button class="host-nav ${state.selected === h.name && state.view === 'host' ? 'active' : ''}" data-host="${safe(h.name)}" type="button"><span class="server-icon">▣</span><span><b>${safe(h.name)}</b><small>${safe(h.user)}@${safe(h.host)}</small></span><span class="chevron">›</span></button>`).join('') : '<div class="empty-side">No connections yet</div>';
  $('host-list').querySelectorAll('[data-host]').forEach(b => b.onclick = () => choose(b.dataset.host));
  $('crumb').textContent = state.view === 'host' ? state.selected : state.view === 'add' ? 'Add connection' : state.view === 'join' ? 'Join a server' : 'Overview';
}
function render() {
  renderSidebar();
  syncShellVisibility();
  if (state.view === 'add') return renderAdd();
  if (state.view === 'join') return renderJoin();
  if (state.view === 'host' && host()) return renderHost(host());
  renderOverview();
}
function renderOverview() {
  $('content').innerHTML = `<div class="eyebrow">SSH ACCESS, WITHOUT THE GUESSWORK</div><h1>Set up a server with confidence.</h1><p class="lead">Create a client key, verify access, move away from root, then turn on key-only SSH and Fail2ban. Each server gets its own guided path.</p><div class="overview-grid"><button class="choice-card" id="start-add" type="button"><span class="choice-icon">＋</span><h2>Connect to a server</h2><p>Save a root or regular account, make a local key, and install its public half.</p><span class="choice-link">Start setup →</span></button><button class="choice-card" id="start-join" type="button"><span class="choice-icon">↗</span><h2>Join from another client</h2><p>Use a 20-minute invitation created on a client that already has access.</p><span class="choice-link">Join a server →</span></button></div><section class="note-card"><b>Lost access to a key?</b><p>If a server still accepts an account password, use that account to install this device’s new public key. If password login is disabled, use another authorized client or your server provider’s console. This app will not weaken an existing key-only policy to regain access.</p></section>`;
  $('start-add').onclick = () => { state.view = 'add'; render(); };
  $('start-join').onclick = () => { state.view = 'join'; render(); };
}
function renderAdd() {
  $('content').innerHTML = `<div class="eyebrow">NEW CONNECTION</div><h1>Tell us how you reach the server.</h1><p class="lead">Use an account that can currently log in. Starting with root is okay; we will guide you to a regular sudo account before changing SSH policy.</p><form class="form-card" id="add-form"><div class="form-grid"><label>Connection name<input name="name" required placeholder="englandsoftware" pattern="[A-Za-z0-9][A-Za-z0-9_.-]*"></label><label>SSH address<input name="target" required placeholder="root@server.example.com"></label><label>SSH port<input name="port" type="number" min="1" max="65535" value="22" required></label><label>Existing private key path <small>Optional</small><input name="identity" placeholder="Leave blank to use sshable’s local key"></label></div><div class="form-note">If the key file does not exist, OpenSSH will guide you through creating one. You can set a local key passphrase in the live session.</div><button class="primary" type="submit">Save connection and prepare key →</button></form><button class="text-link" id="add-back" type="button">← Back to overview</button>`;
  $('add-back').onclick = () => { state.view = 'overview'; render(); };
  $('add-form').onsubmit = async e => { e.preventDefault(); const f = new FormData(e.target); await start({action:'add', name:f.get('name').trim(), target:f.get('target').trim(), port:Number(f.get('port')), identity:f.get('identity').trim()}); };
}
function renderJoin() {
  $('content').innerHTML = `<div class="eyebrow">NEW CLIENT</div><h1>Join a server by invitation.</h1><p class="lead">On a client that already has access, open the server and choose “Invite another client.” Use the temporary username and password here within 20 minutes.</p><form class="form-card" id="join-form"><div class="form-grid"><label>Name on this device<input name="name" required placeholder="englandsoftware" pattern="[A-Za-z0-9][A-Za-z0-9_.-]*"></label><label>Permanent account and host<input name="target" required placeholder="alice@server.example.com"></label><label>SSH port<input name="port" type="number" min="1" max="65535" value="22" required></label><label>Temporary username<input name="tempUser" required placeholder="sshable_..."></label><label class="full">Existing private key path <small>Optional</small><input name="identity" placeholder="Leave blank to create/use this device’s key"></label></div><div class="form-note">You will enter the temporary password in the live session. The new public key is added to the permanent account, then key login is tested before the connection is saved.</div><button class="primary" type="submit">Join and verify access →</button></form><button class="text-link" id="join-back" type="button">← Back to overview</button>`;
  $('join-back').onclick = () => { state.view = 'overview'; render(); };
  $('join-form').onsubmit = async e => { e.preventDefault(); const f = new FormData(e.target); await start({action:'join', name:f.get('name').trim(), target:f.get('target').trim(), port:Number(f.get('port')), tempUser:f.get('tempUser').trim(), identity:f.get('identity').trim()}); };
}
function step(number, title, body, action, label, disabled = false, kind = '') {
  return `<div class="step ${kind}"><div class="step-num">${number}</div><div class="step-body"><h3>${title}</h3><p>${body}</p>${action ? `<button class="${kind === 'danger' ? 'outline-danger' : 'secondary'}" data-action="${action}" ${disabled ? 'disabled' : ''} type="button">${label}</button>` : ''}</div></div>`;
}
function renderHost(h) {
  const isRoot = h.user === 'root';
  const checked = mark(h.name, 'keycheck');
  const audited = mark(h.name, 'audit');
  const rootKeyMissing = isRoot && !h.keyPresent;
  const status = audited ? '<span class="status good">VERIFIED SECURE</span>' : checked ? '<span class="status good">KEY LOGIN VERIFIED</span>' : '<span class="status">SETUP IN PROGRESS</span>';
  $('content').innerHTML = `<div class="host-heading"><div><div class="eyebrow">SERVER WORKSPACE</div><h1>${safe(h.name)}</h1><p class="lead host-address">${safe(h.user)}@${safe(h.host)} <span>·</span> port ${safe(h.port)}</p></div><div class="host-controls"><button class="primary" data-action="connect" type="button">${state.session?.running && state.session.action === 'connect' && state.session.name === h.name ? (shellVisible ? 'Focus console' : 'Show console') : 'Connect to server'}</button>${status}</div></div><div class="summary-grid"><div class="summary-card"><small>CURRENT ACCOUNT</small><b>${isRoot ? 'Root access' : 'Regular user'}</b><span>${isRoot ? 'Create a regular sudo account before hardening.' : 'Use this account to test and secure SSH.'}</span></div><div class="summary-card"><small>LOCAL IDENTITY</small><b>${h.keyPresent ? 'Private key on this device' : 'Private key missing'}</b><span class="path">${safe(h.identity)}</span></div></div><div class="section-heading"><div><span class="eyebrow">GUIDED SETUP</span><h2>${isRoot ? 'Move safely off root' : 'Finish key-only access'}</h2></div><p>Complete each step and keep a working login until the final verification passes.</p></div><div class="steps">${isRoot ? rootSteps(h, rootKeyMissing) : userSteps(h, checked)}</div>${publicKeySection(h)}${!isRoot ? clientSection(h, audited) : ''}<section class="detail-card"><div class="detail-head"><span class="eyebrow">SAVED CONNECTION</span><h2>Manage connection</h2></div><p>Rename this connection or remove it from this device. Removing it leaves your local key files and server access intact.</p><div class="manage-actions"><button class="secondary" data-action="rename" type="button">Rename connection</button><button class="outline-danger" data-action="remove" type="button">Delete connection</button></div></section>`;
  $('content').querySelectorAll('[data-action]').forEach(b => b.onclick = () => handleHostAction(b.dataset.action, h));
  const copy = $('copy-public'); if (copy) copy.onclick = async () => { try { await navigator.clipboard.writeText(h.publicKey); toast('Public key copied. Share this line only with an already authorized client.'); } catch { toast('Select and copy the public key manually.'); } };
  const auth = $('authorize-form'); if (auth) auth.onsubmit = async e => { e.preventDefault(); const pub = new FormData(e.target).get('publicKey').trim(); await start({action:'authorize', name:h.name, publicKey:pub}); };
}
function rootSteps(h, missing) {
  return step('01', 'Confirm your root key still works', missing ? 'The saved private key is missing. Point a new connection at a working key, use a still-enabled password, or recover through your provider console.' : 'Test a fresh key-only login. If the server no longer has this key but still accepts a root password, reinstall its public key first.', 'keycheck', 'Test root key login') +
    step('02', 'Create a regular sudo account', 'The app installs this device’s public key, tests the new account, and shows its generated sudo password once. Record that password.', 'provision-form', 'Set up non-root account', !mark(h.name, 'keycheck')) +
    step('03', 'Secure using the new account', 'Open the new saved connection in the sidebar. Verify its key, then apply SSH policy and Fail2ban there.', '', '');
}
function userSteps(h, checked) {
  return step('01', 'Verify this device’s key', 'Make a fresh connection using only the saved key. A successful test is required before hardening.', 'keycheck', 'Test key login') +
    step('02', 'Enable key-only SSH and Fail2ban', 'Disables SSH passwords and root SSH, checks sshd, reloads it, tests key access again, then configures the Fail2ban sshd jail. Keep provider console access available.', 'secure', 'Apply security settings', !checked) +
    step('03', 'Audit the live server', 'Check effective SSH settings for the regular user and root, verify a new key login, and confirm the Fail2ban jail is running.', 'audit', 'Run final audit', !checked);
}
function publicKeySection(h) {
  return `<section class="detail-card"><div class="detail-head"><div><span class="eyebrow">THIS DEVICE</span><h2>Public key & recovery</h2></div></div><p>The private key stays at <code>${safe(h.identity)}</code>. Only the public line below should be shared. An authorized client can add it to this account without reopening password login.</p>${h.publicKey ? `<div class="public-row"><code>${safe(h.publicKey)}</code><button class="secondary" type="button" id="copy-public">Copy</button></div>` : '<div class="warning">No valid public key file was found. If the private key still exists, re-save the connection to recover its public half.</div>'}<div class="recovery"><b>Can still log in with a password?</b><p>Install this public key, then test it. If passwords are already disabled, authorize the public key from another trusted client or your provider console.</p><button class="secondary" data-action="copy-id" type="button">Install this device’s key</button></div></section>`;
}
function clientSection(h, audited) {
  const oldRoot = state.hosts.find(x => x.user === 'root' && x.host === h.host && x.port === h.port && x.identity === h.identity);
  return `<section class="detail-card"><div class="detail-head"><div><span class="eyebrow">MORE DEVICES</span><h2>Add another client</h2></div></div><p>Each device creates its own private key. Choose the simpler path for your situation:</p><div class="client-options"><div><b>Public key transfer</b><p>Paste the new device’s public key here. This adds it to ${safe(h.user)} without replacing existing clients.</p><form id="authorize-form"><textarea name="publicKey" required placeholder="ssh-ed25519 AAAA… device-name"></textarea><button class="secondary" type="submit">Authorize public key</button></form></div><div><b>Temporary invitation</b><p>Create a 20-minute account for a new device. It joins from its own local app, then runs security setup to remove the invitation.</p><button class="secondary" data-action="invite" type="button" ${audited ? '' : 'disabled'}>Invite another client</button><small>${audited ? 'Keep the live session open to copy its one-time credentials.' : 'Run the final audit first.'}</small></div></div><div class="cleanup"><b>Root key cleanup</b><p>After the final audit succeeds, remove this device’s key from root’s authorized_keys. This does not touch other keys. The saved root connection can then be removed locally.</p><button class="outline-danger" data-action="revoke-root" type="button" ${audited ? '' : 'disabled'}>Remove this key from root</button>${oldRoot ? `<button class="outline-danger" data-action="remove-root-entry" data-root="${safe(oldRoot.name)}" type="button" ${mark(h.name, 'revoke-root') ? '' : 'disabled'}>Forget old root connection</button>` : ''}</div></section>`;
}
async function handleHostAction(action, h) {
  if (action === 'connect' && state.session?.running) {
    if (state.session.action === 'connect' && state.session.name === h.name) showSession();
    else toast('Finish the current session before connecting.');
    return;
  }
  if (action === 'rename') {
    const newName = prompt('New name for this connection:', h.name);
    if (newName === null || newName.trim() === h.name) return;
    return start({action:'rename', name:h.name, newName:newName.trim()});
  }
  if (action === 'remove' && !confirm(`Delete the saved connection “${h.name}” from this device? Local key files and server access will remain.`)) return;
  if (action === 'remove-root-entry') {
    const oldRoot = state.hosts.find(x => x.user === 'root' && x.host === h.host && x.port === h.port && x.identity === h.identity);
    if (!oldRoot || !confirm('Forget the saved root connection on this device? This leaves local key files intact.')) return;
    return start({action:'remove', name:oldRoot.name});
  }
  if (action === 'provision-form') {
    const newUser = prompt('New regular Linux username (for example: admin):');
    if (!newUser) return;
    const newName = prompt('Name for the new saved connection:', h.name + '-admin');
    if (!newName) return;
    return start({action:'provision', name:h.name, newUser:newUser.trim(), newName:newName.trim()});
  }
  if (action === 'secure' && !confirm('Apply server-wide key-only SSH, disable root SSH, and install Fail2ban? Keep your provider console available.')) return;
  if (action === 'revoke-root' && !confirm('Remove this device’s public key from root on this server? Continue only after the audit passed.')) return;
  if (action === 'invite' && !confirm('Create a 20-minute password-enabled onboarding account on this server?')) return;
  await start({action, name:h.name});
}
async function start(request) {
  try {
    const result = await post('/api/action', request);
    state.session = {id:result.id, action:request.action, name:request.name, newName:request.newName, running:true};
    $('terminal-title').textContent = ({add:'Preparing connection', join:'Joining server', keycheck:'Testing key access', 'copy-id':'Installing public key', provision:'Creating regular account', secure:'Securing SSH and Fail2ban', audit:'Auditing server', authorize:'Authorizing public key', invite:'Creating invitation', 'revoke-root':'Removing root key', rename:'Renaming connection', remove:'Deleting connection'})[request.action] || 'Working';
    $('terminal-output').textContent = '';
    $('terminal-result').textContent = '';
    resetShell();
    shellVisible = request.action === 'connect';
    syncShellVisibility();
    showSession();
  } catch (err) { toast(err.message); }
}
function resetShell() {
  shellResizeObserver?.disconnect();
  shellResizeObserver = null;
  shellTerm?.dispose();
  shellTerm = null; shellFit = null; shellOffset = 0; shellInputQueue = Promise.resolve(); shellResizeSize = '';
  shellSelectedText = '';
  $('shell-copy').disabled = true;
  $('shell-terminal').classList.remove('ended');
  $('shell-terminal-inner').replaceChildren();
}
function sendShell(data, binary = false) {
  const id = state.session?.id;
  if (!id || !state.session.running) return;
  const chars = Array.from(data);
  for (let i = 0; i < chars.length; i += 2000) {
    const part = chars.slice(i, i + 2000).join('');
    shellInputQueue = shellInputQueue.then(() => post('/api/input', {id, ...(binary ? {binary:btoa(part)} : {data:part})})).catch(err => {
      if (state.session?.running && state.session.id === id) toast(err.message);
    });
  }
}
function fitShell() {
  if (!shellTerm || $('console-dock').classList.contains('hidden') || !$('shell-terminal-inner').clientWidth) return;
  shellFit.fit();
}
function resizeShell(cols, rows) {
  if (state.session?.running && state.session.action === 'connect' && cols >= 20 && cols <= 500 && rows >= 5 && rows <= 300) {
    const size = `${state.session.id}:${cols}:${rows}`;
    if (size === shellResizeSize) return;
    shellResizeSize = size;
    post('/api/resize', {id:state.session.id, cols, rows}).catch(err => {
      if (shellResizeSize === size) shellResizeSize = '';
      toast(err.message);
    });
  }
}
function syncShellVisibility() {
  const visible = shellVisible && state.session?.action === 'connect' && state.view === 'host' && state.selected === state.session.name;
  $('console-dock').classList.toggle('hidden', !visible);
  if (visible && shellTerm) requestAnimationFrame(fitShell);
}
function showShell() {
  state.selected = state.session.name;
  state.view = 'host';
  shellVisible = true;
  $('shell-title').textContent = `${state.session.name} · ${host()?.user || 'SSH'}@${host()?.host || 'server'}`;
  $('shell-status').textContent = state.session.running ? 'Type in the console. Select text to copy it.' : 'Connection closed. Select text to copy it.';
  $('shell-disconnect').classList.toggle('hidden', !state.session.running);
  $('shell-paste').disabled = !state.session.running;
  render();
  if (!shellTerm) {
      $('shell-terminal-inner').style.setProperty('--terminal-font-size', shellFontSize + 'px');
      shellTerm = new Terminal({
        cursorBlink: false, cursorStyle: 'block', scrollback: 5000,
        fontFamily: 'Menlo, Monaco, Consolas, "Liberation Mono", monospace',
        fontSize: shellFontSize, lineHeight: 1.25, letterSpacing: 0, fontWeight: 'normal', fontWeightBold: 'bold',
        theme: {
          background: '#101010', foreground: '#f2f2f2', cursor: '#ffffff', cursorAccent: '#101010',
          selectionBackground: '#596474', black: '#8b949e', red: '#ff777d', green: '#92df90',
          yellow: '#f2d36e', blue: '#92bdff', magenta: '#dfa4f4', cyan: '#81d9e2', white: '#e6e6e6',
          brightBlack: '#afb8c2', brightRed: '#ffa1a5', brightGreen: '#b2edaf',
          brightYellow: '#ffe59e', brightBlue: '#b7d2ff', brightMagenta: '#ecc4fa',
          brightCyan: '#a8e9ef', brightWhite: '#ffffff'
        }
      });
      shellFit = new FitAddon.FitAddon();
      shellTerm.loadAddon(shellFit);
      shellTerm.open($('shell-terminal-inner'));
      shellTerm.onData(data => sendShell(data));
      shellTerm.onBinary(data => sendShell(data, true));
      shellTerm.onResize(({cols, rows}) => resizeShell(cols, rows));
      shellTerm.attachCustomKeyEventHandler(event => {
        if (event.type === 'keydown' && (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'c' && shellTerm.hasSelection()) {
          copyShellSelection();
          return false;
        }
        return true;
      });
      shellTerm.onSelectionChange(() => {
        shellSelectedText = shellTerm.getSelection();
        $('shell-copy').disabled = !shellSelectedText;
      });
      shellResizeObserver = new ResizeObserver(() => requestAnimationFrame(fitShell));
      shellResizeObserver.observe($('shell-terminal-inner'));
  }
  requestAnimationFrame(() => { fitShell(); resizeShell(shellTerm.cols, shellTerm.rows); shellTerm?.focus(); $('console-dock').scrollIntoView({block:'start',behavior:'smooth'}); });
}
function showSession() {
  if (state.session?.action === 'connect') return showShell();
  $('terminal-backdrop').classList.remove('hidden');
  $('terminal-form').classList.toggle('hidden', !state.session?.running);
  $('terminal-input').focus();
}
function cleanTerminal(s) {
  return s.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '').replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '').replace(/\r(?!\n)/g, '\n').replace(/\x08/g, '');
}
async function poll() {
  try {
    const requestedOffset = shellOffset;
    const data = await api('/api/session?offset=' + requestedOffset); const current = data.session;
    if (!current) return;
    if (current.running && (!state.session || current.id !== state.session.id)) {
      state.session = {id:current.id, action:current.action, name:current.name, newName:current.newName, running:true};
      $('terminal-title').textContent = 'Continuing ' + current.action;
      resetShell();
      showSession();
      if (requestedOffset !== 0) return;
    }
    if (state.session && current.id === state.session.id) {
      if (current.action === 'connect') {
        if (shellTerm) {
          if (current.reset) shellTerm.reset();
          if (current.chunk) shellTerm.write(Uint8Array.from(atob(current.chunk), c => c.charCodeAt(0)));
          shellOffset = current.offset;
        }
      } else {
        const output = $('terminal-output');
        if (output.textContent !== cleanTerminal(current.output)) { output.textContent = cleanTerminal(current.output); output.scrollTop = output.scrollHeight; }
      }
      if (!current.running && state.session.running) {
        state.session.running = false;
        $('terminal-form').classList.add('hidden');
        if (current.action === 'connect') {
          if (current.success) {
            shellVisible = false;
            resetShell();
            shellOffset = current.offset;
            syncShellVisibility();
            toast('SSH connection closed.');
          } else {
            $('shell-disconnect').classList.add('hidden');
            $('shell-paste').disabled = true;
            $('shell-terminal').classList.add('ended');
            $('shell-status').textContent = 'Connection ended. Review the console output.';
          }
        } else {
          $('terminal-result').textContent = current.success ? 'Completed successfully. You can close this session.' : 'This step stopped. Read the message above before retrying.';
          $('terminal-result').className = 'terminal-result ' + (current.success ? 'success' : 'failure');
        }
        if (current.success) {
          const a = state.session.action, n = state.session.name;
          if (n) { state.marks[n] ??= {}; state.marks[n][a] = true; }
          if (a === 'add' || a === 'join') { state.selected = n; state.view = 'host'; }
          if (a === 'provision') { state.selected = state.session.newName; state.view = 'host'; }
          if (a === 'rename') {
            state.marks[state.session.newName] = state.marks[n] || {};
            delete state.marks[n];
            if (state.selected === n) state.selected = state.session.newName;
          }
          if (a === 'remove') {
            delete state.marks[n];
            if (state.selected === n) { state.selected = ''; state.view = 'overview'; }
          }
          await reload();
        }
        if (current.action === 'connect') render();
      }
    }
  } catch (err) { /* A stopped local server will be apparent on the next action. */ }
}
$('new-button').onclick = () => { state.view = 'add'; render(); };
$('terminal-close').onclick = () => {
  if (state.session?.running && !confirm('The SSH action is still running. Close this window and return later?')) return;
  $('terminal-backdrop').classList.add('hidden');
};
$('shell-hide').onclick = () => { shellVisible = false; render(); };
$('shell-disconnect').onclick = async () => {
  if (!state.session?.running || state.session.action !== 'connect') return;
  try { await post('/api/disconnect', {id:state.session.id}); }
  catch (err) { toast(err.message); }
};
async function copyShellSelection() {
  const selected = shellSelectedText || shellTerm?.getSelection();
  if (!selected) return;
  const previousFocus = document.activeElement;
  const field = document.createElement('textarea');
  field.value = selected;
  field.style.cssText = 'position:fixed;left:-9999px;top:0';
  try {
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand('copy');
    if (!copied) await navigator.clipboard.writeText(selected);
    $('shell-status').textContent = 'Selection copied to clipboard.';
  } catch { toast('Clipboard access failed. Check your browser clipboard permissions.'); }
  finally { field.remove(); previousFocus?.focus(); }
}
$('shell-copy').onclick = copyShellSelection;
$('shell-paste').onclick = async () => {
  if (!state.session?.running || state.session.action !== 'connect') return;
  try {
    const pasted = await navigator.clipboard.readText();
    if (pasted) sendShell(pasted);
    shellTerm?.focus();
  } catch { toast('Clipboard access failed. Use Command-V or Control-V in the console.'); }
};
$('shell-terminal').addEventListener('copy', event => {
  const selected = shellTerm?.getSelection();
  if (selected && event.clipboardData) {
    event.clipboardData.setData('text/plain', selected);
    event.preventDefault();
  }
});
function changeShellFont(delta) {
  shellFontSize = Math.max(13, Math.min(24, shellFontSize + delta));
  $('shell-terminal-inner').style.setProperty('--terminal-font-size', shellFontSize + 'px');
  if (shellTerm) {
    shellTerm.options.fontSize = shellFontSize;
    requestAnimationFrame(fitShell);
  }
  $('terminal-font-down').disabled = shellFontSize === 13;
  $('terminal-font-up').disabled = shellFontSize === 24;
}
$('terminal-font-down').onclick = () => changeShellFont(-1);
$('terminal-font-up').onclick = () => changeShellFont(1);
window.addEventListener('resize', () => requestAnimationFrame(fitShell));
$('terminal-show').onchange = e => { $('terminal-input').type = e.target.checked ? 'text' : 'password'; };
$('terminal-form').onsubmit = async e => {
  e.preventDefault(); const input = $('terminal-input');
  try { await post('/api/input', {id:state.session.id, line:input.value}); input.value = ''; input.focus(); }
  catch (err) { toast(err.message); }
};
reload().catch(err => toast(err.message));
async function pollLoop() {
  await poll();
  setTimeout(pollLoop, state.session?.running && state.session.action === 'connect' ? 120 : 600);
}
pollLoop();
