import { h } from '../ui/dom.js';
import { icons } from '../ui/icons.js';
import { t } from '../core/i18n.js';

/**
 * Sperrschirm. Im Mockup gibt es keine echte Verschluesselung: Biometrie ist
 * eine Attrappe mit kurzer Animation, die Passphrase der Rueckfallweg. Falsche
 * Eingabe laesst das Feld wackeln und zeigt einen Hinweis — keine Sperrzeit,
 * die im Prototyp nur im Weg stuende.
 */
export function lockView(app) {
  // Grob zeigende Geraete haben Gesichtserkennung, Zeigergeraete den Sensor.
  const face = window.matchMedia('(pointer: coarse)').matches;

  const hint = h('div', { class: 'muted', style: {
    fontSize: 'var(--t-small)', minHeight: '20px', color: '#E5A3A3', textAlign: 'center'
  } }, '');

  const field = h('input', {
    id: 'lock-pass', type: 'password', placeholder: t('lock-passphrase'),
    autocomplete: 'current-password',
    style: {
      width: '100%', padding: '14px 16px', borderRadius: '14px', border: 0,
      background: 'rgba(255,255,255,.10)', color: '#F4F6F4', fontSize: '17px',
      textAlign: 'center', letterSpacing: '.12em'
    },
    onKeydown: (e) => { if (e.key === 'Enter') submit(); }
  });

  const submit = () => {
    const value = field.value.trim();
    if (!value) {
      hint.textContent = t('lock-empty');
      shake();
      return;
    }
    app.unlock();
  };

  const shake = () => {
    field.style.animation = 'none';
    void field.offsetWidth;
    field.style.animation = 'lock-shake .32s';
  };

  const bio = h('button', {
    class: 'lock-bio', type: 'button',
    onClick: (e) => {
      const el = e.currentTarget;
      el.classList.add('busy');
      setTimeout(() => app.unlock(), 620);
    }
  }, face ? icons.faceId(40) : icons.touchId(40));

  return h('div', { class: 'lock' },
    h('div', { class: 'lock-inner' },
      h('div', { class: 'lock-mark' }, h('span', {}, 'open'), h('span', { class: 'om' }, 'om')),
      h('div', { class: 'lock-title' }, t('lock-title')),
      bio,
      h('div', { class: 'lock-bio-label' }, face ? t('lock-face') : t('lock-touch')),
      h('div', { class: 'lock-or' }, t('lock-or')),
      field,
      hint,
      h('button', { class: 'lock-submit', type: 'button', onClick: submit }, t('lock-unlock'))));
}
