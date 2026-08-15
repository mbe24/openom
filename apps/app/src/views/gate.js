import { h } from '../ui/dom.js';

// The pre-unlock gate: welcome / provision / recovery-code / unlock. This is the STRUCTURAL,
// minimal version — it reuses the .lock full-screen container and plain English strings so the
// boot/gate flow works and is testable. Step 3 replaces the copy with i18n, adds RTL logical
// styling, tokens (light/dark), a real <form> + password-manager semantics, and a11y.
//
// The gate owns its DOM: App.render() (the global re-render path) early-returns while a gate is
// up, so a font-load or resize can't wipe a half-typed passphrase. Gate-internal updates go
// through App.renderGate(), only on explicit user actions (submit/transition).

const passStyle = {
  width: '100%',
  padding: '14px 16px',
  borderRadius: '14px',
  border: 0,
  background: 'rgba(255,255,255,.10)',
  color: '#F4F6F4',
  fontSize: '17px',
  textAlign: 'center',
};

const mark = () => h('div', { class: 'lock-mark' }, h('span', {}, 'open'), h('span', { class: 'om' }, 'om'));
const title = (text) => h('div', { class: 'lock-title', style: { maxWidth: '34ch' } }, text);
const errorLine = (app) =>
  h('div', {
    role: 'alert',
    style: { minHeight: '20px', color: '#E5A3A3', textAlign: 'center', fontSize: 'var(--t-small)' },
  }, app.gateError || '');
const passField = (id, placeholder, autocomplete) =>
  h('input', { id, type: 'password', placeholder, autocomplete, autocapitalize: 'off', spellcheck: 'false', style: passStyle });
const primary = (label, opts = {}) => h('button', { class: 'lock-submit', type: 'button', ...opts }, label);
const ghost = (label, onClick) =>
  h('button', { class: 'lock-submit', type: 'button', style: { background: 'transparent', border: '1px solid rgba(255,255,255,.2)' }, onClick }, label);

export function gateView(app) {
  switch (app.gate) {
    case 'provision':
      return provisionScreen(app);
    case 'recovery':
      return recoveryScreen(app);
    case 'unlock':
      return unlockScreen(app);
    default:
      return welcomeScreen(app);
  }
}

function welcomeScreen(app) {
  return h('div', { class: 'lock' }, h('div', { class: 'lock-inner' },
    mark(),
    title('Your private, end-to-end-encrypted family tree'),
    primary('Create your tree', { onClick: () => app.startCreate() }),
    ghost('Explore a demo', () => app.startDemo())));
}

function provisionScreen(app) {
  const p1 = passField('gate-pass', 'Choose a passphrase', 'new-password');
  const p2 = passField('gate-pass2', 'Confirm passphrase', 'new-password');
  const submit = () => app.doProvision(p1.value, p2.value);
  p2.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  return h('div', { class: 'lock' }, h('div', { class: 'lock-inner' },
    mark(),
    title('Create a passphrase — it encrypts your tree. If you forget it, only your recovery code can restore access.'),
    p1, p2, errorLine(app),
    primary(app.gateBusy ? 'Securing…' : 'Create', { disabled: app.gateBusy, onClick: submit })));
}

function recoveryScreen(app) {
  return h('div', { class: 'lock' }, h('div', { class: 'lock-inner' },
    mark(),
    title('Save your recovery code. It is the ONLY way back if you forget your passphrase — we cannot recover it for you.'),
    h('div', {
      style: {
        // Base32 ASCII in an RTL doc reorders without this; force LTR + isolate.
        direction: 'ltr', unicodeBidi: 'isolate',
        fontFamily: 'monospace', fontSize: '18px', letterSpacing: '.06em',
        padding: '14px 16px', background: 'rgba(255,255,255,.08)', borderRadius: '12px',
        userSelect: 'all', textAlign: 'center', wordBreak: 'break-all', width: '100%',
      },
    }, app.gateRecoveryCode || ''),
    primary('I saved it — continue', { onClick: () => app.gateContinue() })));
}

function unlockScreen(app) {
  const p = passField('gate-pass', 'Enter your passphrase', 'current-password');
  const submit = () => app.doUnlock(p.value);
  p.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  return h('div', { class: 'lock' }, h('div', { class: 'lock-inner' },
    mark(),
    title('Unlock your tree'),
    p, errorLine(app),
    primary(app.gateBusy ? 'Unlocking…' : 'Unlock', { disabled: app.gateBusy, onClick: submit })));
}
