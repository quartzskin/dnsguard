'use strict';
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const DEFAULTS = {
  listen: '127.0.0.1',
  port: 5353,
  upstream: '1.1.1.1',
  upstreamTimeoutMs: 3000,
  blockMode: 'null',
  blocklists: [],
  sources: [],
  allowFile: 'allow.txt',
  denyFile: 'deny.txt',
  db: 'dnsguard.db',
  privacy: false,
  retentionDays: 30,
  maxLogRows: 100000,
  cacheSize: 2000,
  uiPort: 5380,
  allowOpen: false,
};

function parseUpstream(s) {
  s = String(s);
  let host = s, port = 53;
  const m = /^\[(.+)\]:(\d+)$/.exec(s) || (!net.isIPv6(s) && /^(.+):(\d+)$/.exec(s));
  if (m) { host = m[1]; port = +m[2]; }
  if (!net.isIP(host)) throw new Error(`upstream must be an IP address (optionally :port), got "${s}"`);
  if (port < 1 || port > 65535) throw new Error('upstream port out of range');
  return { host, port };
}

function isLoopback(ip) {
  const v = String(ip).toLowerCase().replace(/^::ffff:/, '');
  return net.isIPv4(v) ? v.startsWith('127.') : v === '::1';
}

function validate(c) {
  if (!Number.isInteger(c.port) || c.port < 0 || c.port > 65535) throw new Error('port must be 0-65535');
  if (!Number.isInteger(c.uiPort) || c.uiPort < 0 || c.uiPort > 65535) throw new Error('uiPort must be 0-65535');
  if (!['null', 'nxdomain'].includes(c.blockMode)) throw new Error('blockMode must be "null" or "nxdomain"');
  if (!net.isIP(c.listen)) throw new Error('listen must be an IP address');
  if (!Array.isArray(c.blocklists) || !Array.isArray(c.sources)) throw new Error('blocklists and sources must be arrays');
  for (const s of c.sources) {
    if (!s || typeof s.url !== 'string' || typeof s.file !== 'string') throw new Error('each source needs "url" and "file"');
    if (!/^https?:\/\//i.test(s.url)) throw new Error('source url must be http(s): ' + s.url);
  }
  c.upstreamAddr = parseUpstream(c.upstream);
  return c;
}

// Relative paths in the config file are resolved against the config file's folder.
function loadConfig(file, overrides = {}) {
  let raw = {};
  let dir = process.cwd();
  if (file && fs.existsSync(file)) {
    dir = path.dirname(path.resolve(file));
    try {
      raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      throw new Error(`cannot parse ${file}: ${e.message}`);
    }
  } else if (file && file !== 'dnsguard.json') {
    throw new Error('config file not found: ' + file);
  }
  const c = { ...DEFAULTS, ...raw };
  for (const [k, v] of Object.entries(overrides)) if (v !== undefined) c[k] = v;
  const abs = p => path.resolve(dir, p);
  c.allowFile = abs(c.allowFile);
  c.denyFile = abs(c.denyFile);
  if (c.db !== ':memory:') c.db = abs(c.db);
  c.blocklists = [...c.blocklists, ...c.sources.map(s => s.file)].map(abs);
  c.sources = c.sources.map(s => ({ ...s, file: abs(s.file) }));
  c.dir = dir;
  return validate(c);
}

const SAMPLE = {
  listen: '127.0.0.1',
  port: 5353,
  upstream: '1.1.1.1',
  blockMode: 'null',
  blocklists: ['lists/custom.txt'],
  sources: [],
  allowFile: 'allow.txt',
  denyFile: 'deny.txt',
  db: 'dnsguard.db',
  privacy: false,
  retentionDays: 30,
  maxLogRows: 100000,
};

module.exports = { loadConfig, isLoopback, parseUpstream, SAMPLE, DEFAULTS };
