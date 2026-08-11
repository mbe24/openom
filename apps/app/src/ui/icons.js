import { svg } from './dom.js';

const wrap = (children, size = 24) => {
  const root = svg('svg', { viewBox: '0 0 28 28', width: size, height: size, fill: 'none',
    stroke: 'currentColor', 'stroke-width': 2 });
  for (const c of children) root.appendChild(c);
  return root;
};

export const icons = {
  back: (s) => wrap([svg('path', { d: 'M17 5 9 14l8 9', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })], s),
  tree: (s) => wrap([
    svg('rect', { x: 3, y: 3, width: 9.5, height: 7.5, rx: 2.4 }),
    svg('rect', { x: 15.5, y: 3, width: 9.5, height: 7.5, rx: 2.4 }),
    svg('rect', { x: 9.25, y: 17.5, width: 9.5, height: 7.5, rx: 2.4 }),
    svg('path', { d: 'M7.75 10.5v3.5h12.5v-3.5M14 14v3.5' })
  ], s),
  descendants: (s) => {
    const el = wrap([
      svg('rect', { x: 3, y: 3, width: 9.5, height: 7.5, rx: 2.4 }),
      svg('rect', { x: 15.5, y: 3, width: 9.5, height: 7.5, rx: 2.4 }),
      svg('rect', { x: 9.25, y: 17.5, width: 9.5, height: 7.5, rx: 2.4 }),
      svg('path', { d: 'M7.75 10.5v3.5h12.5v-3.5M14 14v3.5' })
    ], s);
    el.setAttribute('style', 'transform: scaleY(-1)');
    return el;
  },
  graph: (s) => wrap([
    svg('circle', { cx: 7, cy: 7, r: 3.2 }),
    svg('circle', { cx: 21, cy: 11, r: 3.2 }),
    svg('circle', { cx: 12, cy: 21, r: 3.2 }),
    svg('path', { d: 'M9.6 8.8 18 10M9 10l2 8' })
  ], s),
  person: (s) => wrap([
    svg('circle', { cx: 14, cy: 9.5, r: 4.6 }),
    svg('path', { d: 'M5.5 24c0-4.7 3.8-8 8.5-8s8.5 3.3 8.5 8', 'stroke-linecap': 'round' })
  ], s),
  people: (s) => wrap([
    svg('circle', { cx: 16.5, cy: 9, r: 4.2 }),
    svg('path', { d: 'M9 23.5c0-4.2 3.4-7.2 7.5-7.2s7.5 3 7.5 7.2', 'stroke-linecap': 'round' }),
    svg('circle', { cx: 7.6, cy: 10.6, r: 3.2 }),
    svg('path', { d: 'M3.2 23.5c0-3.2 1.5-5.7 4-6.5', 'stroke-linecap': 'round' })
  ], s),
  settings: (s) => wrap([
    svg('path', { d: 'M4 9h6M16 9h8M4 19h12M22 19h2', 'stroke-linecap': 'round' }),
    svg('circle', { cx: 13, cy: 9, r: 3 }),
    svg('circle', { cx: 19, cy: 19, r: 3 })
  ], s),
  search: (s) => wrap([
    svg('circle', { cx: 12, cy: 12, r: 7 }),
    svg('path', { d: 'M17.5 17.5 24 24', 'stroke-linecap': 'round' })
  ], s),
  // Der Faecher spannt nur die obere Haelfte auf — ohne Versatz saesse er in
  // der 28er-Box drei Einheiten zu tief.
  fan: (s) => wrap([
    svg('path', { d: 'M4 19a10 10 0 0 1 20 0', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M9 19a5 5 0 0 1 10 0', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M14 19v-1' })
  ], s),
  data: (s) => wrap([
    svg('path', { d: 'M14 4v12M9 11l5 5 5-5', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M4 20v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2', 'stroke-linecap': 'round' })
  ], s),
  fit: (s) => wrap([
    svg('path', { d: 'M4 10V6a2 2 0 0 1 2-2h4M18 4h4a2 2 0 0 1 2 2v4M24 18v4a2 2 0 0 1-2 2h-4M10 24H6a2 2 0 0 1-2-2v-4', 'stroke-linecap': 'round' }),
    svg('circle', { cx: 14, cy: 14, r: 3 })
  ], s),
  edit: (s) => wrap([
    svg('path', { d: 'M19.5 4.5a2.6 2.6 0 0 1 3.7 3.7L10.5 21 5 23l2-5.5z', 'stroke-linejoin': 'round' }),
    svg('path', { d: 'M17.2 6.8 21 10.6' })
  ], s),
  folder: (s) => wrap([
    svg('path', { d: 'M4 8.5a2 2 0 0 1 2-2h4.2l2.2 2.6H22a2 2 0 0 1 2 2v9.4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z',
      'stroke-linejoin': 'round' })
  ], s),
  trash: (s) => wrap([
    svg('path', { d: 'M5.5 8h17M11 8V5.5h6V8M7.5 8l1 15a2 2 0 0 0 2 1.9h7a2 2 0 0 0 2-1.9l1-15',
      'stroke-linecap': 'round', 'stroke-linejoin': 'round' })
  ], s),
  faceId: (s) => wrap([
    svg('path', { d: 'M4 10V6.5A2.5 2.5 0 0 1 6.5 4H10M18 4h3.5A2.5 2.5 0 0 1 24 6.5V10M24 18v3.5a2.5 2.5 0 0 1-2.5 2.5H18M10 24H6.5A2.5 2.5 0 0 1 4 21.5V18', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M10.5 11.5v2M17.5 11.5v2M14 12v3.5h-1.4', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M10.5 18.5c1 1.1 2.2 1.6 3.5 1.6s2.5-.5 3.5-1.6', 'stroke-linecap': 'round' })
  ], s),
  touchId: (s) => wrap([
    svg('path', { d: 'M6.5 12a7.5 7.5 0 0 1 15 0v3.5', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M10 12a4 4 0 0 1 8 0v5.5a3.5 3.5 0 0 1-.6 2', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M14 12v6.5c0 1.6-.5 3-1.5 4.2', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M6.8 17.5c.5-1 .7-2 .7-3', 'stroke-linecap': 'round' }),
    svg('path', { d: 'M21 19.5c-.4 1.2-1 2.3-1.8 3.2', 'stroke-linecap': 'round' })
  ], s),
  expand: (s) => wrap([
    svg('path', { d: 'M17 4h7v7M24 4l-8.5 8.5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }),
    svg('path', { d: 'M11 24H4v-7M4 24l8.5-8.5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })
  ], s),
  panel: (s) => wrap([
    svg('rect', { x: 4, y: 5, width: 20, height: 18, rx: 3.5 }),
    svg('path', { d: 'M11.5 5v18' })
  ], s),
  close: (s) => wrap([svg('path', { d: 'M8 8l12 12M20 8L8 20', 'stroke-linecap': 'round' })], s),
  plus: (s) => wrap([svg('path', { d: 'M14 6v16M6 14h16', 'stroke-linecap': 'round' })], s),
  minus: (s) => wrap([svg('path', { d: 'M6 14h16', 'stroke-linecap': 'round' })], s),
  list: (s) => wrap([
    svg('circle', { cx: 6, cy: 7, r: 2.6 }), svg('circle', { cx: 6, cy: 14, r: 2.6 }), svg('circle', { cx: 6, cy: 21, r: 2.6 }),
    svg('path', { d: 'M12 7h12M12 14h12M12 21h8', 'stroke-linecap': 'round' })
  ], s)
};
