'use strict';
const { EventEmitter } = require('node:events');

const CLIENTS = ['192.0.2.10', '192.0.2.11', '192.0.2.12'];
const ALLOWED = ['www.example.org', 'docs.example.net', 'cdn.example.com', 'api.sample-app.test', 'mail.example.org', 'static.example.net', 'updates.sample-app.test'];
const BLOCKED = [
  ['ads.tracker-example.com', 'list:demo-ads.txt'],
  ['telemetry.metrics-example.net', 'list:demo-ads.txt'],
  ['pixel.adnetwork-example.org', 'list:demo-ads.txt'],
  ['beacon.stats-example.com', 'deny-file'],
];

const pick = a => a[Math.floor(Math.random() * a.length)];

// Synthetic traffic for screenshots and trying the UI without touching real DNS.
function startDemo(store, intervalMs = 700) {
  const guard = new EventEmitter();
  const emit = () => {
    const r = Math.random();
    const base = { ts: Date.now(), client: pick(CLIENTS), type: pick(['A', 'A', 'AAAA', 'HTTPS']), rcode: 0, ms: 5 + Math.floor(Math.random() * 40) };
    let ev;
    if (r < 0.28) {
      const [name, reason] = pick(BLOCKED);
      ev = { ...base, name, action: 'block', reason, cached: false };
    } else {
      ev = { ...base, name: pick(ALLOWED), action: 'allow', reason: null, cached: r > 0.65 };
    }
    store.log(ev);
    guard.emit('query', ev);
  };
  for (let i = 0; i < 40; i++) emit();
  const timer = setInterval(emit, intervalMs);
  return { guard, stop: () => clearInterval(timer) };
}

module.exports = { startDemo };
