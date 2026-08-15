import { h, svg } from '../ui/dom.js';

// The pre-unlock gate: welcome / provision / recovery-code / recover / unlock.
//
// The gate owns its DOM: App.render() (the global re-render path) early-returns while a gate is
// up, so a font-load or resize can't wipe a half-typed passphrase. Gate-internal updates go
// through App.renderGate() (which also focuses the first field), only on explicit user actions.
//
// Structure notes:
//  - Each screen is a real <form>: password managers only recognise input + submit inside one,
//    and a native submit gives Enter-to-submit and the on-screen keyboard's "go" for free.
//  - Colours come from the design tokens, so the gate follows the app's light/dark mode.
//  - Copy is English here; the i18n pass swaps the literals for t() keys.

const revealIcon = (shown) =>
  shown
    ? svg('svg', { width: 20, height: 20, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': 'true' },
        svg('path', { d: 'M3 3l18 18', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round' }),
        svg('path', { d: 'M10.6 6.2A9 9 0 0121 12c-.5 1-1.2 1.9-2 2.7M6.5 7.5A13 13 0 003 12c1.7 3.3 5 5.5 9 5.5 1.2 0 2.3-.2 3.3-.6', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round' }))
    : svg('svg', { width: 20, height: 20, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': 'true' },
        svg('path', { d: 'M3 12c1.7-3.3 5-5.5 9-5.5s7.3 2.2 9 5.5c-1.7 3.3-5 5.5-9 5.5s-7.3-2.2-9-5.5z', stroke: 'currentColor', 'stroke-width': 1.6 }),
        svg('circle', { cx: 12, cy: 12, r: 2.6, stroke: 'currentColor', 'stroke-width': 1.6 }));

const mark = () => h('div', { class: 'lock-mark' }, h('span', {}, 'open'), h('span', { class: 'om' }, 'om'));
const title = (text) => h('div', { class: 'lock-title' }, text);
const errorLine = (app) => h('div', { class: 'lock-error', role: 'alert', 'aria-live': 'assertive' }, app.gateError || '');

// A password field with an eye toggle. Returns the field element; read `.pass.value`.
function passField(id, label, autocomplete) {
  const input = h('input', {
    id, type: 'password', 'aria-label': label, placeholder: label, autocomplete,
    autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', class: 'lock-input',
  });
  const toggle = h('button', {
    type: 'button', class: 'lock-reveal', 'aria-label': 'Show passphrase', 'aria-pressed': 'false',
    onClick: () => {
      const shown = input.type === 'text';
      input.type = shown ? 'password' : 'text';
      toggle.setAttribute('aria-pressed', String(!shown));
      toggle.setAttribute('aria-label', shown ? 'Show passphrase' : 'Hide passphrase');
      toggle.replaceChildren(revealIcon(!shown));
      input.focus();
    },
  }, revealIcon(false));
  const field = h('div', { class: 'lock-field' }, input, toggle);
  field.pass = input;
  return field;
}

// A <form> that runs `onSubmit` and never actually navigates.
function form(onSubmit, ...kids) {
  return h('form', {
    class: 'lock-form', novalidate: 'true',
    onSubmit: (e) => { e.preventDefault(); onSubmit(); },
  }, ...kids);
}

const shell = (...kids) => h('div', { class: 'lock' }, h('div', { class: 'lock-inner' }, ...kids));
const primary = (label, opts = {}) => h('button', { class: 'lock-submit', type: 'submit', ...opts }, label);
const ghost = (label, onClick) => h('button', { class: 'lock-ghost', type: 'button', onClick }, label);

export function gateView(app) {
  switch (app.gate) {
    case 'provision':
      return provisionScreen(app);
    case 'recovery':
      return recoveryScreen(app);
    case 'recover':
      return recoverScreen(app);
    case 'unlock':
      return unlockScreen(app);
    default:
      return welcomeScreen(app);
  }
}

function welcomeScreen(app) {
  const kids = [
    mark(),
    title('Your private, end-to-end-encrypted family tree'),
    primary('Start your family tree', { type: 'button', onClick: () => app.startCreate() }),
  ];
  // The demo is dev/marketing only (build-time flag); a production user never sees it.
  if (app.demoEnabled) kids.push(ghost('Explore a demo', () => app.startDemo()));
  return shell(...kids);
}

function provisionScreen(app) {
  const p1 = passField('gate-pass', 'Choose a passphrase', 'new-password');
  const p2 = passField('gate-pass2', 'Confirm passphrase', 'new-password');
  const submit = () => app.doProvision(p1.pass.value, p2.pass.value);
  return shell(
    mark(),
    title('Create a passphrase — it encrypts your tree. If you forget it, only your recovery code can restore access.'),
    form(submit, p1, p2, errorLine(app),
      primary(app.gateBusy ? 'Securing…' : 'Create', { disabled: app.gateBusy })));
}

function recoveryScreen(app) {
  return shell(
    mark(),
    title('Save your recovery code. It is the ONLY way back if you forget your passphrase — we cannot recover it for you.'),
    h('div', { id: 'gate-recovery-code', class: 'lock-code' }, app.gateRecoveryCode || ''),
    primary('I saved it — continue', { type: 'button', onClick: () => app.gateContinue() }));
}

function unlockScreen(app) {
  const p = passField('gate-pass', 'Enter your passphrase', 'current-password');
  const submit = () => app.doUnlock(p.pass.value);
  return shell(
    mark(),
    title('Unlock your tree'),
    form(submit, p, errorLine(app),
      primary(app.gateBusy ? 'Unlocking…' : 'Unlock', { disabled: app.gateBusy })),
    ghost('Forgot your passphrase?', () => app.startRecover()));
}

function recoverScreen(app) {
  const code = h('input', {
    id: 'gate-code', type: 'text', placeholder: 'Recovery code', 'aria-label': 'Recovery code',
    autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', class: 'lock-input',
    // The recovery code is ASCII base32; keep it LTR + isolated even under a RTL locale.
    style: { direction: 'ltr', unicodeBidi: 'isolate', padding: '14px 16px', fontFamily: 'ui-monospace, monospace', letterSpacing: '.06em' },
  });
  const p1 = passField('gate-pass', 'New passphrase', 'new-password');
  const p2 = passField('gate-pass2', 'Confirm new passphrase', 'new-password');
  const submit = () => app.doRecover(code.value, p1.pass.value, p2.pass.value);
  return shell(
    mark(),
    title('Enter your recovery code and choose a new passphrase.'),
    form(submit, code, p1, p2, errorLine(app),
      primary(app.gateBusy ? 'Recovering…' : 'Recover', { disabled: app.gateBusy })));
}
