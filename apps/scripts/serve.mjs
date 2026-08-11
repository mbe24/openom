// Winziger statischer Server fuer die Entwicklung. Kein Paket noetig — die App
// besteht aus ES-Modulen, die der Browser direkt laedt; sie braucht nur eine
// echte Herkunft (file:// verbietet Module und IndexedDB je nach Browser).
//
//   node scripts/serve.mjs                              → App auf :5173
//   node scripts/serve.mjs --open preview/desktop.html  → Vorschau statt App

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const PORT = Number(process.env.PORT) || 5173;
const ROOT = process.cwd();
const openIdx = process.argv.indexOf('--open');
const START = openIdx > -1 ? process.argv[openIdx + 1] : 'app/index.html';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ftl': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2'
};

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  // Umleiten statt ausliefern: die Startseite unter "/" auszugeben laesst alle
  // relativen Pfade darin gegen die Wurzel aufloesen — die Seite bliebe leer.
  if (url.pathname === '/') {
    res.writeHead(302, { location: '/' + START }).end();
    return;
  }
  
  const path = url.pathname;
  // normalize + Praefixpruefung: kein Ausbrechen aus dem Projektordner.
  const file = join(ROOT, normalize(path).replace(/^(\.\.[/\\])+/, ''));
  if (!file.startsWith(ROOT)) { res.writeHead(403).end('forbidden'); return; }
  try {
    const body = await readFile(file);
    res.writeHead(200, {
      'content-type': TYPES[extname(file)] ?? 'application/octet-stream',
      // Entwicklung: nichts zwischenspeichern, sonst sieht man Aenderungen nicht.
      'cache-control': 'no-store'
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
  }
}).listen(PORT, () => {
  console.log('openom → http://localhost:' + PORT + '/  (' + START + ')');
});
