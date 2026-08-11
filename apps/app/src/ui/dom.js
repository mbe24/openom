// Winziger DOM-Helfer statt Framework: h() erzeugt Knoten, render() tauscht
// einen Bereich aus. Reaktivitaet kommt aus tree.revision, nicht aus Events.
export function h(tag, props = null, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'html') el.innerHTML = v;
      else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, String(v));
    }
  }
  add(el, children);
  return el;
}

function add(el, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) add(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

export function svg(tag, props = null, ...children) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  if (props) for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined || v === false) continue;
    el.setAttribute(k, String(v));
  }
  for (const c of children) if (c) el.appendChild(c);
  return el;
}

export function mount(target, node) {
  target.replaceChildren(node);
  return node;
}

export function initials(person) {
  if (!person) return '?';
  const given = (person.given ?? '').trim().split(/\s+/).filter(Boolean);
  const surname = (person.surname ?? '').trim();
  // Zwei Vornamen unterscheiden Geschwister besser als Vor- plus Nachname.
  const letters = given.length > 1
    ? (given[0][0] ?? '') + (given[1][0] ?? '')
    : (given[0]?.[0] ?? '') + (surname[0] ?? '');
  return letters.toUpperCase() || '?';
}

export function fullName(person, fallback = '—') {
  if (!person) return fallback;
  const name = [person.given, person.surname].filter(Boolean).join(' ').trim();
  return name || fallback;
}

export function toast(message) {
  const el = h('div', { class: 'toast', role: 'status' }, message);
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2600);
}
