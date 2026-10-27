'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { setRule, Filter } = require('./blocklist');

const ASSETS = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
};
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function startUi({ guard, store, cfg, port, host = '127.0.0.1' }) {
  const clients = new Set();
  let allowedHosts = new Set();

  guard.on('query', ev => {
    const line = `data: ${JSON.stringify(ev)}\n\n`;
    for (const res of clients) res.write(line);
  });

  const send = (res, code, body, type = 'application/json') => {
    res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff' });
    res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
  };

  const server = http.createServer((req, res) => {
    // Host check blocks DNS rebinding; Origin check blocks cross-site POSTs.
    if (!allowedHosts.has(req.headers.host)) return send(res, 403, { error: 'bad host' });
    const origin = req.headers.origin;
    if (origin && !allowedHosts.has(origin.replace(/^http:\/\//, ''))) return send(res, 403, { error: 'bad origin' });
    const url = new URL(req.url, 'http://x');

    if (req.method === 'GET' && ASSETS[url.pathname]) {
      const [file, type] = ASSETS[url.pathname];
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'ui', file)), type);
    }
    if (req.method === 'GET' && url.pathname === '/api/stats') return send(res, 200, store.stats());
    if (req.method === 'GET' && url.pathname === '/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', 'Content-Security-Policy': CSP });
      res.write(`event: hello\ndata: ${JSON.stringify({ recent: store.recent(50), stats: store.stats(), privacy: !!cfg.privacy })}\n\n`);
      clients.add(res);
      req.on('close', () => clients.delete(res));
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/rule') {
      if (!origin || !/^application\/json/.test(req.headers['content-type'] || '')) return send(res, 403, { error: 'origin and json body required' });
      let body = '';
      req.on('data', d => {
        body += d;
        if (body.length > 4096) req.destroy();
      });
      req.on('end', () => {
        try {
          const { domain, action } = JSON.parse(body);
          const d = setRule(cfg, domain, action);
          guard.filter = Filter.load(cfg);
          send(res, 200, { ok: true, domain: d, action });
        } catch (e) {
          send(res, 400, { error: e.message });
        }
      });
      return;
    }
    send(res, 404, { error: 'not found' });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const p = server.address().port;
      allowedHosts = new Set([`127.0.0.1:${p}`, `localhost:${p}`]);
      resolve({
        url: `http://127.0.0.1:${p}/`,
        port: p,
        close: () => new Promise(r => {
          for (const c of clients) c.end();
          server.close(r);
          server.closeAllConnections();
        }),
      });
    });
  });
}

module.exports = { startUi };
