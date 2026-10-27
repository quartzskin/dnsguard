#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { loadConfig, parseUpstream, isLoopback, SAMPLE } = require('../src/config');
const { Filter, setRule } = require('../src/blocklist');
const { DnsGuard, udpQuery, tcpQuery } = require('../src/server');
const { Store } = require('../src/store');
const { startUi } = require('../src/ui');
const { updateLists } = require('../src/update');
const { startDemo } = require('../src/demo');
const dns = require('../src/dns');

const HELP = `usage: dnsguard <command> [options]

  run               start the DNS filter (default 127.0.0.1:5353)
  ui                start the filter plus the web UI on 127.0.0.1:5380
  update            download the blocklists named in "sources" (--dry-run to preview)
  init              write a starter dnsguard.json, allow.txt, deny.txt and lists/custom.txt
  check <domain>    show whether a domain would be blocked, without any network
  allow <domain>    add to the allow file     block <domain>   add to the deny file
  stats             print totals and top lists from the query log
  log               print recent queries (--limit N)
  query <name> [type]   ask a running dnsguard (or --server host:port)

options: --config FILE  --port N  --listen IP  --allow-open  --upstream IP[:port]  --ui-port N
         --block-mode null|nxdomain  --privacy  --no-open  --browser EXE  --demo  --json
`;

const BOOL = new Set(['allow-open', 'privacy', 'no-open', 'dry-run', 'demo', 'json', 'help']);

function parseArgs(argv) {
  const flags = {}, pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { pos.push(a); continue; }
    const [k, inline] = a.slice(2).split('=');
    if (BOOL.has(k)) flags[k] = true;
    else if (inline !== undefined) flags[k] = inline;
    else if (i + 1 < argv.length) flags[k] = argv[++i];
    else throw new Error(`--${k} needs a value`);
  }
  return { flags, pos };
}

function num(v, name) {
  if (v === undefined) return undefined;
  if (!/^\d+$/.test(v)) throw new Error(`--${name} must be a number`);
  return +v;
}

function configFrom(flags) {
  return loadConfig(flags.config || 'dnsguard.json', {
    port: num(flags.port, 'port'),
    uiPort: num(flags['ui-port'], 'ui-port'),
    listen: flags.listen,
    upstream: flags.upstream,
    blockMode: flags['block-mode'],
    privacy: flags.privacy ? true : undefined,
    allowOpen: flags['allow-open'] ? true : undefined,
  });
}

function loadFilter(cfg) {
  const f = Filter.load(cfg);
  for (const w of f.warnings) console.error('warning: ' + w);
  return f;
}

function openBrowser(url, exe) {
  const cmd = exe || process.env.BROWSER;
  let child;
  if (cmd) child = spawn(cmd, [url], { detached: true, stdio: 'ignore' });
  else if (process.platform === 'win32') child = spawn('cmd', ['/c', 'start', '""', url], { detached: true, stdio: 'ignore' });
  else child = spawn(process.platform === 'darwin' ? 'open' : 'xdg-open', [url], { detached: true, stdio: 'ignore' });
  child.on('error', () => console.error('could not launch a browser, open the URL yourself'));
  child.unref();
}

async function startGuard(cfg) {
  if (!isLoopback(cfg.listen)) {
    if (!cfg.allowOpen) throw new Error(`refusing to listen on ${cfg.listen}: that exposes an open resolver to your network; pass --allow-open to do it anyway`);
    console.error(`WARNING: listening on non-loopback address ${cfg.listen}. Anyone who can reach it can use this as an open resolver (reflection/amplification risk). dnsguard has no client allow-list.`);
  }
  const store = new Store(cfg.db, cfg);
  const guard = new DnsGuard(cfg, { filter: loadFilter(cfg), store });
  guard.on('error', e => console.error('error: ' + e.message));
  guard.on('warning', e => console.error('log write failed: ' + e.message));
  try {
    await guard.start();
  } catch (e) {
    if (e.code === 'EADDRINUSE' || e.code === 'EACCES') {
      throw new Error(`cannot bind ${cfg.listen}:${cfg.port} (${e.code}); pick another with --port`);
    }
    throw e;
  }
  console.log(`dnsguard listening on ${cfg.listen}:${guard.port} (udp+tcp), upstream ${cfg.upstream}`);
  console.log(`${guard.filter.size} blocked domains loaded, block mode "${cfg.blockMode}"${cfg.privacy ? ', privacy mode (no client info logged)' : ''}`);
  return { guard, store };
}

function printHowTo(cfg, port) {
  console.log(`\ntry it:   nslookup -port=${port} example.com ${cfg.listen}`);
  console.log('dnsguard does not touch your system DNS settings. Windows cannot point the system resolver at a');
  console.log('non-standard port, so to use it system-wide run with --port 53 (needs admin) and set the adapter');
  console.log(`DNS server to ${cfg.listen} yourself. Ctrl+C to stop.\n`);
}

function waitForExit(stop) {
  const quit = async () => { await stop(); process.exit(0); };
  process.on('SIGINT', quit);
  process.on('SIGTERM', quit);
}

const commands = {
  async run(flags) {
    const cfg = configFrom(flags);
    const { guard, store } = await startGuard(cfg);
    printHowTo(cfg, guard.port);
    if (flags.json) guard.on('query', e => console.log(JSON.stringify(e)));
    else guard.on('query', e => console.log(`${e.action === 'block' ? 'BLOCK' : e.cached ? 'cache' : 'allow'}  ${e.type.padEnd(5)} ${e.name}${e.reason ? '  [' + e.reason + ']' : ''}`));
    waitForExit(async () => { await guard.stop(); store.close(); });
  },

  async ui(flags) {
    const cfg = configFrom(flags);
    let guard, store, stop;
    if (flags.demo) {
      cfg.db = ':memory:';
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dnsguard-demo-'));
      cfg.allowFile = path.join(dir, 'allow.txt');
      cfg.denyFile = path.join(dir, 'deny.txt');
      store = new Store(':memory:', cfg);
      const demo = startDemo(store);
      guard = demo.guard;
      stop = async () => { demo.stop(); fs.rmSync(dir, { recursive: true, force: true }); };
      console.log('demo mode: synthetic traffic, no DNS server started');
    } else {
      ({ guard, store } = await startGuard(cfg));
      stop = async () => { await guard.stop(); store.close(); };
    }
    const ui = await startUi({ guard, store, cfg, port: cfg.uiPort });
    console.log('ui: ' + ui.url);
    if (!flags['no-open']) openBrowser(ui.url, flags.browser);
    if (!flags.demo) printHowTo(cfg, guard.port);
    waitForExit(async () => { await ui.close(); await stop(); });
  },

  async update(flags) {
    const cfg = configFrom(flags);
    const r = await updateLists(cfg, { dryRun: !!flags['dry-run'] });
    if (r.failed) process.exitCode = 1;
  },

  async init() {
    const files = {
      'dnsguard.json': JSON.stringify(SAMPLE, null, 2) + '\n',
      'allow.txt': '# domains (and their subdomains), *.glob patterns or /regex/ lines that are never blocked\n',
      'deny.txt': '# domains always blocked, wins over allow.txt\n',
      'lists/custom.txt': '# hosts format or one domain per line\n',
    };
    for (const [f, body] of Object.entries(files)) {
      if (fs.existsSync(f)) { console.log(`${f} exists, left alone`); continue; }
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, body);
      console.log('wrote ' + f);
    }
    console.log('add download URLs under "sources" in dnsguard.json, then run: dnsguard update');
  },

  async check(flags, pos) {
    if (!pos[0]) throw new Error('usage: dnsguard check <domain>');
    const r = loadFilterFor(flags).check(pos[0]);
    console.log(`${pos[0]}: ${r.action}${r.reason ? ' (' + r.reason + ')' : ''}`);
    if (r.action === 'block') process.exitCode = 2;
  },

  async allow(flags, pos) { ruleCmd(flags, pos, 'allow'); },
  async block(flags, pos) { ruleCmd(flags, pos, 'block'); },

  async stats(flags) {
    const cfg = configFrom(flags);
    const store = new Store(cfg.db, cfg);
    const s = store.stats();
    if (flags.json) return console.log(JSON.stringify(s, null, 2));
    console.log(`queries ${s.total}, blocked ${s.blocked}, cache hit rate ${(s.cacheHitRate * 100).toFixed(1)}%`);
    const show = (title, rows, key) => {
      console.log(`\n${title}`);
      if (!rows.length) console.log('  (none)');
      for (const r of rows) console.log(`  ${String(r.count).padStart(6)}  ${r[key]}`);
    };
    show('top blocked', s.topBlocked, 'name');
    show('top domains', s.topDomains, 'name');
    show('top clients', s.topClients, 'client');
  },

  async log(flags) {
    const cfg = configFrom(flags);
    const store = new Store(cfg.db, cfg);
    for (const r of store.recent(num(flags.limit, 'limit') || 30)) {
      console.log(`${new Date(r.ts).toISOString()}  ${(r.client || '-').padEnd(15)} ${r.action.padEnd(5)} ${r.type.padEnd(5)} ${r.name}${r.cached ? '  (cached)' : ''}`);
    }
  },

  async query(flags, pos) {
    if (!pos[0]) throw new Error('usage: dnsguard query <name> [type]');
    const cfg = configFrom(flags);
    const server = parseUpstream(flags.server || `${cfg.listen}:${cfg.port}`);
    const type = dns.typeNumber(pos[1] || 'A');
    const buf = dns.build({ id: Math.floor(Math.random() * 65536), rd: 1, questions: [{ name: pos[0], type, class: 1 }] });
    let resp = await udpQuery(server, buf, 4000);
    if (resp.readUInt16BE(2) & 0x200) resp = await tcpQuery(server, buf, 4000);
    const m = dns.parse(resp);
    const rcode = Object.keys(dns.RCODES).find(k => dns.RCODES[k] === m.rcode) || m.rcode;
    console.log(`status ${rcode}, ${m.answers.length} answer(s)`);
    for (const a of m.answers) {
      const d = a.data;
      const text = Buffer.isBuffer(d) ? `${d.length} bytes` : typeof d === 'object' ? JSON.stringify(d, (k, v) => v && v.type === 'Buffer' ? Buffer.from(v.data).toString('hex') : v) : d;
      console.log(`  ${a.name}  ${a.ttl}  ${dns.typeName(a.type)}  ${text}`);
    }
    if (m.rcode !== 0) process.exitCode = 1;
  },
};

function loadFilterFor(flags) {
  return loadFilter(configFrom(flags));
}

function ruleCmd(flags, pos, action) {
  if (!pos[0]) throw new Error(`usage: dnsguard ${action} <domain>`);
  const cfg = configFrom(flags);
  const file = action === 'allow' ? cfg.allowFile : cfg.denyFile;
  if (flags['dry-run']) return console.log(`would add ${pos[0]} to ${file}`);
  console.log(`${setRule(cfg, pos[0], action)} added to ${file}`);
}

async function main() {
  const { flags, pos } = parseArgs(process.argv.slice(2));
  const cmd = pos.shift();
  if (!cmd || flags.help || cmd === 'help') return process.stdout.write(HELP);
  if (!commands[cmd]) throw new Error(`unknown command "${cmd}"\n\n${HELP}`);
  await commands[cmd](flags, pos);
}

main().catch(e => {
  console.error('dnsguard: ' + e.message);
  process.exit(1);
});
