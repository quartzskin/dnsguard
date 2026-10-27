'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const dns = require('../src/dns');
const { DnsGuard, udpQuery, tcpQuery } = require('../src/server');
const { Filter } = require('../src/blocklist');
const { Store } = require('../src/store');
const { startUi } = require('../src/ui');

const { TYPES } = dns;

// UDP+TCP fake upstream. Big answers get TC over UDP and the full set over TCP.
async function fakeUpstream() {
  const seen = { udp: [], tcp: [] };
  const answer = (q, over) => {
    const name = q.questions[0].name;
    if (name === 'big.test') {
      const answers = Array.from({ length: 40 }, (_, i) => ({ name, type: TYPES.A, ttl: 60, data: `10.0.0.${i}` }));
      return over === 'udp' ? dns.truncate(dns.build({ id: q.id, qr: 1, questions: q.questions, answers }), dns.parse(dns.build({ id: q.id, qr: 1, questions: q.questions }))) : dns.build({ id: q.id, qr: 1, questions: q.questions, answers });
    }
    if (name === 'missing.test') return dns.build({ id: q.id, qr: 1, rcode: 3, questions: q.questions });
    return dns.build({ id: q.id, qr: 1, rd: 1, ra: 1, questions: q.questions, answers: [{ name, type: q.questions[0].type === TYPES.AAAA ? TYPES.AAAA : TYPES.A, ttl: 120, data: q.questions[0].type === TYPES.AAAA ? '2001:db8::5' : '203.0.113.5' }] });
  };
  const udp = dgram.createSocket('udp4');
  await new Promise(r => udp.bind(0, '127.0.0.1', r));
  const port = udp.address().port;
  udp.on('message', (m, r) => {
    const q = dns.parse(m);
    seen.udp.push(q.questions[0].name);
    if (q.questions[0].name === 'silent.test') return;
    let out = answer(q, 'udp');
    if (q.questions[0].name === 'big.test') out[2] |= 0x02;
    udp.send(out, r.port, r.address);
  });
  const tcp = net.createServer(s => {
    s.on('data', d => {
      const q = dns.parse(d.subarray(2));
      seen.tcp.push(q.questions[0].name);
      const out = answer(q, 'tcp');
      const h = Buffer.alloc(2);
      h.writeUInt16BE(out.length);
      s.write(Buffer.concat([h, out]));
    });
  });
  await new Promise(r => tcp.listen(port, '127.0.0.1', r));
  return { port, seen, close: () => { udp.close(); tcp.close(); } };
}

async function setup(over = {}) {
  const up = await fakeUpstream();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dnsguard-s-'));
  fs.writeFileSync(path.join(dir, 'l.txt'), '0.0.0.0 ads.example.com\n');
  const cfg = {
    listen: '127.0.0.1', port: 0, upstreamAddr: { host: '127.0.0.1', port: up.port }, upstreamTimeoutMs: 300,
    blockMode: 'null', privacy: false, cacheSize: 100, uiPort: 0,
    allowFile: path.join(dir, 'allow.txt'), denyFile: path.join(dir, 'deny.txt'), blocklists: [path.join(dir, 'l.txt')], ...over,
  };
  const store = new Store(':memory:', cfg);
  const guard = new DnsGuard(cfg, { filter: Filter.load(cfg), store });
  await guard.start();
  const addr = { host: '127.0.0.1', port: guard.port };
  const ask = (name, type = TYPES.A, via = udpQuery) =>
    via(addr, dns.build({ id: Math.floor(Math.random() * 65535), rd: 1, questions: [{ name, type, class: 1 }] }), 1500).then(dns.parse);
  const done = async () => { await guard.stop(); up.close(); store.close(); };
  return { up, guard, store, cfg, addr, ask, done, dir };
}

test('allowed query is forwarded, then cached with aged TTL', async () => {
  const t = await setup();
  try {
    const a = await t.ask('www.example.org');
    assert.equal(a.answers[0].data, '203.0.113.5');
    const b = await t.ask('www.example.org');
    assert.equal(b.answers[0].data, '203.0.113.5');
    assert.equal(t.up.seen.udp.filter(n => n === 'www.example.org').length, 1);
    const [first, second] = t.store.recent(2);
    assert.equal(first.cached, false);
    assert.equal(second.cached, true);
    assert.equal(t.store.stats().cacheHitRate, 0.5);
    const six = await t.ask('www.example.org', TYPES.AAAA);
    assert.equal(six.answers[0].data, '2001:db8::5');
  } finally { await t.done(); }
});

test('blocked names get 0.0.0.0 / :: and never reach upstream', async () => {
  const t = await setup();
  try {
    const a = await t.ask('sub.ads.example.com');
    assert.equal(a.rcode, 0);
    assert.equal(a.answers[0].data, '0.0.0.0');
    assert.equal((await t.ask('ads.example.com', TYPES.AAAA)).answers[0].data, '::');
    assert.equal((await t.ask('ads.example.com', TYPES.HTTPS)).answers.length, 0);
    assert.deepEqual(t.up.seen.udp, []);
    assert.equal(t.store.stats().blocked, 3);
  } finally { await t.done(); }
});

test('nxdomain block mode', async () => {
  const t = await setup({ blockMode: 'nxdomain' });
  try {
    const a = await t.ask('ads.example.com');
    assert.equal(a.rcode, 3);
    assert.equal(a.answers.length, 0);
  } finally { await t.done(); }
});

test('allow file overrides a blocklist, and reload picks up changes', async () => {
  const t = await setup();
  try {
    fs.writeFileSync(t.cfg.allowFile, '*.example.com\n');
    t.guard.filter = Filter.load(t.cfg);
    assert.equal((await t.ask('ads.example.com')).answers[0].data, '203.0.113.5');
  } finally { await t.done(); }
});

test('truncated UDP upstream answer falls back to TCP', async () => {
  const t = await setup();
  try {
    const small = await t.ask('big.test');
    assert.equal(small.tc, 1);
    assert.equal(small.answers.length, 0);
    const r = await t.ask('big.test', TYPES.A, tcpQuery);
    assert.equal(r.answers.length, 40);
    assert.deepEqual(t.up.seen.tcp, ['big.test']);
  } finally { await t.done(); }
});

test('NXDOMAIN passes through, silent upstream gives SERVFAIL', async () => {
  const t = await setup();
  try {
    assert.equal((await t.ask('missing.test')).rcode, 3);
    assert.equal((await t.ask('silent.test')).rcode, 2);
  } finally { await t.done(); }
});

test('answers also work over TCP', async () => {
  const t = await setup();
  try {
    assert.equal((await t.ask('www.example.org', TYPES.A, tcpQuery)).answers[0].data, '203.0.113.5');
    assert.equal((await t.ask('ads.example.com', TYPES.A, tcpQuery)).answers[0].data, '0.0.0.0');
  } finally { await t.done(); }
});

test('malformed packets do not kill the server', async () => {
  const t = await setup();
  try {
    const sock = dgram.createSocket('udp4');
    const garbage = [Buffer.alloc(0), Buffer.from([1, 2, 3]), Buffer.alloc(12, 0xff), Buffer.from('000100000001000000000000c00c00010001', 'hex'), Buffer.from('00010000000100000000000003777777', 'hex')];
    for (let i = 0; i < 300; i++) garbage.push(Buffer.from(Array.from({ length: 12 + (i % 40) }, (_, j) => (i * 31 + j * 17) & 0xff)));
    for (const g of garbage) sock.send(g, t.guard.port, '127.0.0.1');
    await new Promise(r => setTimeout(r, 200));
    sock.close();
    assert.equal((await t.ask('www.example.org')).answers[0].data, '203.0.113.5');
    const q = dns.build({ id: 5, opcode: 2, questions: [{ name: 'a.test', type: 1 }] });
    assert.equal(dns.parse(await udpQuery(t.addr, q, 1000)).rcode, 4);
  } finally { await t.done(); }
});

test('upstream reply with the right id but another question is ignored', async () => {
  const sock = dgram.createSocket('udp4');
  await new Promise(r => sock.bind(0, '127.0.0.1', r));
  sock.on('message', (m, r) => {
    const q = dns.parse(m);
    const ans = name => dns.build({ id: q.id, qr: 1, questions: [{ name, type: 1, class: 1 }], answers: [{ name, type: TYPES.A, ttl: 60, data: '203.0.113.9' }] });
    sock.send(ans('evil.test'), r.port, r.address);
    sock.send(ans('Real.Test'), r.port, r.address);
  });
  try {
    const addr = { host: '127.0.0.1', port: sock.address().port };
    const resp = dns.parse(await udpQuery(addr, dns.build({ id: 77, rd: 1, questions: [{ name: 'real.test', type: 1, class: 1 }] }), 500));
    assert.equal(resp.questions[0].name.toLowerCase(), 'real.test');
  } finally { sock.close(); }
});

test('upstream reply with only a wrong question times out', async () => {
  const sock = dgram.createSocket('udp4');
  await new Promise(r => sock.bind(0, '127.0.0.1', r));
  sock.on('message', (m, r) => {
    const q = dns.parse(m);
    sock.send(dns.build({ id: q.id, qr: 1, questions: [{ name: 'evil.test', type: 1, class: 1 }] }), r.port, r.address);
  });
  try {
    const addr = { host: '127.0.0.1', port: sock.address().port };
    await assert.rejects(udpQuery(addr, dns.build({ id: 78, rd: 1, questions: [{ name: 'real.test', type: 1, class: 1 }] }), 200), /timeout/);
  } finally { sock.close(); }
});

test('binding a non-loopback address needs allowOpen', async () => {
  const cfg = { listen: '0.0.0.0', port: 0, cacheSize: 1 };
  await assert.rejects(new DnsGuard(cfg).start(), /--allow-open/);
  await assert.rejects(new DnsGuard({ ...cfg, listen: '192.0.2.1' }).start(), /--allow-open/);
  const g = new DnsGuard({ ...cfg, allowOpen: true });
  await g.start();
  await g.stop();
});

test('privacy mode stores no client', async () => {
  const t = await setup({ privacy: true });
  try {
    await t.ask('www.example.org');
    assert.equal(t.store.recent(1)[0].client, null);
  } finally { await t.done(); }
});

function req(port, opts, body) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, ...opts }, res => {
      let d = '';
      res.on('data', c => (d += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d }));
    });
    r.on('error', reject);
    r.end(body);
  });
}

test('ui: Host and Origin checks, static files, rule writes', async () => {
  const t = await setup();
  const ui = await startUi({ guard: t.guard, store: t.store, cfg: t.cfg, port: 0 });
  try {
    const ok = await req(ui.port, { path: '/' });
    assert.equal(ok.status, 200);
    assert.match(ok.body, /<table id="recent"/);
    assert.ok(!/<svg|<canvas/.test(ok.body));
    for (const f of ['/app.js', '/style.css']) assert.equal((await req(ui.port, { path: f })).status, 200);
    assert.ok(!/https?:\/\/(?!127)/.test(ok.body), 'no external URLs in the page');
    assert.match(ok.headers['content-security-policy'], /default-src 'none'/);
    assert.equal((await req(ui.port, { path: '/', headers: { Host: 'evil.test' } })).status, 403);
    assert.equal((await req(ui.port, { path: '/api/stats', headers: { Host: `evil.test:${ui.port}` } })).status, 403);
    const post = (headers, body) => req(ui.port, { path: '/api/rule', method: 'POST', headers: { 'Content-Type': 'application/json', ...headers } }, body);
    const origin = `http://127.0.0.1:${ui.port}`;
    assert.equal((await post({}, '{}')).status, 403);
    assert.equal((await post({ Origin: 'http://evil.test' }, '{"domain":"a.com","action":"block"}')).status, 403);
    assert.equal((await post({ Origin: origin }, 'not json')).status, 400);
    assert.equal((await post({ Origin: origin }, '{"domain":"a b","action":"block"}')).status, 400);
    assert.equal((await req(ui.port, { path: '/api/rule', method: 'POST', headers: { Origin: origin, 'Content-Type': 'text/plain' } }, '{}')).status, 403);

    assert.equal((await t.ask('www.example.org')).answers[0].data, '203.0.113.5');
    assert.equal((await post({ Origin: origin }, '{"domain":"www.example.org","action":"block"}')).status, 200);
    assert.equal(fs.readFileSync(t.cfg.denyFile, 'utf8'), 'www.example.org\n');
    assert.equal((await t.ask('www.example.org')).answers[0].data, '0.0.0.0');
    assert.equal((await post({ Origin: origin }, '{"domain":"ads.example.com","action":"allow"}')).status, 200);
    assert.equal((await t.ask('ads.example.com')).answers[0].data, '203.0.113.5');
    const stats = JSON.parse((await req(ui.port, { path: '/api/stats' })).body);
    assert.ok(stats.total >= 3);
    assert.equal((await req(ui.port, { path: '/nope' })).status, 404);
  } finally { await ui.close(); await t.done(); }
});
