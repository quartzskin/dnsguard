'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Filter, parseList, setRule } = require('../src/blocklist');
const { loadConfig, isLoopback } = require('../src/config');
const { updateLists } = require('../src/update');
const { Store } = require('../src/store');

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'dnsguard-t-'));
}

test('parseList handles hosts, plain, adblock lines and junk', () => {
  const text = [
    '# comment', '127.0.0.1 localhost', '0.0.0.0 ads.example.com # trailing', '::1 ip6-localhost',
    'tracker.example.net', '||adblock.example.org^', '!bang comment', '', 'not a domain line here',
    '0.0.0.0 bad_.-.com', '0.0.0.0 UPPER.Example.COM.', '\u0000\u0001garbage',
  ].join('\r\n');
  const got = parseList(text);
  assert.ok(got.includes('ads.example.com'));
  assert.ok(got.includes('tracker.example.net'));
  assert.ok(got.includes('adblock.example.org'));
  assert.ok(got.includes('upper.example.com'));
  assert.ok(!got.includes('not'));
  assert.ok(!got.some(d => /garbage/.test(d)));
});

test('filter precedence: deny > allow > lists, subdomains match', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'l.txt'), '0.0.0.0 ads.example.com\n0.0.0.0 cdn.tracker.test\n0.0.0.0 evil.test\n');
  fs.writeFileSync(path.join(dir, 'allow.txt'), '# c\ncdn.tracker.test\n*.safe.evil.test\n/^ok\\d+\\.evil\\.test$/\n[bad(\n');
  fs.writeFileSync(path.join(dir, 'deny.txt'), 'cdn.tracker.test\n');
  const f = Filter.load({ blocklists: [path.join(dir, 'l.txt'), path.join(dir, 'missing.txt')], allowFile: path.join(dir, 'allow.txt'), denyFile: path.join(dir, 'deny.txt') });
  assert.equal(f.check('ads.example.com').action, 'block');
  assert.equal(f.check('x.y.ads.example.com').action, 'block');
  assert.equal(f.check('ADS.example.com.').action, 'block');
  assert.equal(f.check('example.com').action, 'allow');
  assert.equal(f.check('notads.example.com').action, 'allow');
  assert.equal(f.check('cdn.tracker.test').reason, 'deny-file');
  assert.equal(f.check('a.safe.evil.test').action, 'allow');
  assert.equal(f.check('ok12.evil.test').action, 'allow');
  assert.equal(f.check('ok.evil.test').action, 'block');
  assert.equal(f.check('').action, 'allow');
  assert.ok(f.warnings.some(w => /missing\.txt/.test(w)));
  assert.ok(f.warnings.some(w => /bad\(/.test(w)));
});

test('setRule moves a domain between allow and deny files', () => {
  const dir = tmp();
  const c = { allowFile: path.join(dir, 'sub', 'a.txt'), denyFile: path.join(dir, 'd.txt') };
  setRule(c, 'Foo.Example.com', 'block');
  assert.equal(fs.readFileSync(c.denyFile, 'utf8'), 'foo.example.com\n');
  setRule(c, 'foo.example.com', 'allow');
  assert.equal(fs.readFileSync(c.denyFile, 'utf8'), '');
  assert.equal(fs.readFileSync(c.allowFile, 'utf8'), 'foo.example.com\n');
  setRule(c, 'foo.example.com', 'clear');
  assert.equal(fs.readFileSync(c.allowFile, 'utf8'), '');
  assert.throws(() => setRule(c, 'bad domain', 'allow'), /valid domain/);
  assert.throws(() => setRule(c, 'a.com\nb.com', 'allow'), /valid domain/);
  assert.throws(() => setRule(c, 'a.com', 'zap'), /unknown action/);
});

test('config validation', () => {
  const dir = tmp();
  const write = o => { const f = path.join(dir, 'c.json'); fs.writeFileSync(f, typeof o === 'string' ? o : JSON.stringify(o)); return f; };
  const c = loadConfig(write({ upstream: '9.9.9.9:5300', sources: [{ url: 'https://x.test/l', file: 'lists/x.txt' }] }));
  assert.deepEqual(c.upstreamAddr, { host: '9.9.9.9', port: 5300 });
  assert.equal(c.port, 5353);
  assert.equal(c.listen, '127.0.0.1');
  assert.equal(c.blocklists[0], path.join(dir, 'lists', 'x.txt'));
  assert.throws(() => loadConfig(write('{nope')), /cannot parse/);
  assert.throws(() => loadConfig(write({ upstream: 'dns.google' })), /IP address/);
  assert.throws(() => loadConfig(write({ port: 70000 })), /port/);
  assert.throws(() => loadConfig(write({ blockMode: 'x' })), /blockMode/);
  assert.throws(() => loadConfig(write({ sources: [{ url: 'file:///etc/passwd', file: 'a' }] })), /http/);
  assert.throws(() => loadConfig(path.join(dir, 'nope.json')), /not found/);
  assert.equal(loadConfig(write({ upstream: '2606:4700:4700::1111' })).upstreamAddr.port, 53);
});

test('isLoopback', () => {
  for (const ip of ['127.0.0.1', '127.1.2.3', '::1', '::ffff:127.0.0.1']) assert.equal(isLoopback(ip), true, ip);
  for (const ip of ['0.0.0.0', '::', '192.168.1.5', '10.0.0.1', '2001:db8::1', 'junk']) assert.equal(isLoopback(ip), false, ip);
});

test('update downloads only configured sources and keeps old file on bad data', async () => {
  const dir = tmp();
  const file = path.join(dir, 'l.txt');
  fs.writeFileSync(file, 'old.example.com\n');
  const cfg = { sources: [{ url: 'https://lists.test/a', file }] };
  const logs = [];
  const log = m => logs.push(m);
  const mk = (ok, body) => async () => ({ ok, status: ok ? 200 : 503, text: async () => body });

  let r = await updateLists(cfg, { log, fetchFn: mk(true, '<html>nothing useful</html>') });
  assert.equal(r.failed, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), 'old.example.com\n');
  r = await updateLists(cfg, { log, fetchFn: mk(false, '') });
  assert.equal(r.failed, 1);
  r = await updateLists(cfg, { log, fetchFn: mk(true, '0.0.0.0 new.example.com\n') });
  assert.equal(r.ok, 1);
  assert.match(fs.readFileSync(file, 'utf8'), /new\.example\.com/);
  let called = false;
  r = await updateLists(cfg, { log, dryRun: true, fetchFn: async () => { called = true; } });
  assert.equal(called, false);
  r = await updateLists({ sources: [] }, { log, fetchFn: async () => { called = true; } });
  assert.equal(called, false);
});

test('store: privacy drops clients, row cap and retention prune', () => {
  const now = Date.now();
  const q = (i, extra = {}) => ({ ts: now, client: '192.0.2.1', name: `n${i}.test`, type: 'A', action: i % 2 ? 'block' : 'allow', ...extra });

  const priv = new Store(':memory:', { privacy: true });
  priv.log(q(1));
  assert.equal(priv.recent(1)[0].client, null);
  assert.deepEqual(priv.stats().topClients, []);

  const s = new Store(':memory:', { maxLogRows: 5, retentionDays: 1 });
  for (let i = 0; i < 20; i++) s.log(q(i));
  s.prune();
  assert.equal(s.stats().total, 5);
  s.log(q(100, { ts: now - 3 * 86400000 }));
  s.prune();
  assert.equal(s.stats().total, 5);
  const st = s.stats();
  assert.equal(st.topClients[0].client, '192.0.2.1');
  assert.ok(st.topBlocked.length > 0);

  const c = new Store(':memory:', {});
  c.log(q(0, { cached: true }));
  c.log(q(2));
  c.log(q(1));
  assert.equal(c.stats().cacheHitRate, 0.5);
});
