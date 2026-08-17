// Tiny static server for development. No package needed — the app is ES modules
// the browser loads directly; it only needs a real origin (file:// blocks
// modules and IndexedDB in some browsers).
//
//   node scripts/serve.mjs                              → app on :5173
//   node scripts/serve.mjs --open preview/desktop.html  → preview instead

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { siteUrl } from './site-url.mjs';

const PORT = Number(process.env.PORT) || 5173;
const ROOT = process.cwd();
const openIdx = process.argv.indexOf('--open');
const START = openIdx > -1 ? process.argv[openIdx + 1] : 'app/index.html';

// Local runs answer from this server; SITE_URL only matters for a deploy.
const LOCAL_URL = 'http://localhost:' + PORT + '/';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ftl': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  // The WASM sealer module (src/vendor/sealer); streaming instantiation needs this exact type.
  '.wasm': 'application/wasm'
};

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  // Redirect instead of serving: handing out the start page at "/" makes every
  // relative path inside it resolve against the root, leaving the page blank.
  if (url.pathname === '/') {
    res.writeHead(302, { location: '/' + START }).end();
    return;
  }
  const path = url.pathname;
  // Brand assets are the repo-root `assets/` (../assets from this server's apps/ cwd) — the single
  // source shared with Tauri/docs. Serve them under /assets, matching what the deploy stages into _site.
  let base, file;
  if (path === '/assets' || path.startsWith('/assets/')) {
    base = join(ROOT, '..', 'assets');
    file = join(base, normalize(path.slice('/assets'.length)).replace(/^(\.\.[/\\])+/, ''));
  } else {
    base = ROOT;
    file = join(base, normalize(path).replace(/^(\.\.[/\\])+/, ''));
  }
  // normalize + prefix check: no escaping the served root.
  if (!file.startsWith(base)) { res.writeHead(403).end('forbidden'); return; }
  try {
    let body = await readFile(file);
    // Same substitution the deploy does, so the placeholder never reaches a
    // browser — locally the origin is this server.
    if (extname(file) === '.html') {
      // Local dev has the demo on by default (set OPENOM_DEMO=0 to match production).
      const demo = process.env.OPENOM_DEMO === '0' ? 'false' : 'true';
      body = body.toString('utf8').replaceAll('%SITE_URL%', LOCAL_URL).replaceAll('%DEMO%', demo);
    }
    res.writeHead(200, {
      'content-type': TYPES[extname(file)] ?? 'application/octet-stream',
      // Development: never cache, otherwise changes stay invisible.
      'cache-control': 'no-store'
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
  }
}).listen(PORT, () => {
  console.log('openom → http://localhost:' + PORT + '/  (' + START + ')');
});
