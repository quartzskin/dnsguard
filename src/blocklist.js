'use strict';
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const DOMAIN_RE = /^(?=.{3,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$/;

function normalize(name) {
  return String(name).trim().toLowerCase().replace(/\.$/, '');
}

function isDomain(name) {
  return DOMAIN_RE.test(name);
}

// Accepts hosts files ("0.0.0.0 ads.example.com"), plain domain lists and ||domain^ adblock lines.
function parseList(text) {
  const out = [];
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/\s+#.*$|^\s*[#!].*$/, '').trim();
    if (!line) continue;
    const adblock = /^\|\|([^/^*|]+)\^?$/.exec(line);
    if (adblock) {
      const d = normalize(adblock[1]);
      if (isDomain(d)) out.push(d);
      continue;
    }
    const tokens = line.split(/\s+/);
    const rest = net.isIP(tokens[0]) ? tokens.slice(1) : tokens.length === 1 ? tokens : [];
    for (const t of rest) {
      const d = normalize(t);
      if (isDomain(d)) out.push(d);
    }
  }
  return out;
}

function parseRule(line) {
  const m = /^\/(.+)\/$/.exec(line);
  if (m) return { text: line, test: new RegExp(m[1], 'i') };
  if (line.includes('*')) {
    const body = line.split('*').map(p => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
    return { text: line, test: new RegExp('^' + body + '$', 'i') };
  }
  return null;
}

function readLines(file) {
  try {
    return fs.readFileSync(file, 'utf8').split(/\r?\n/);
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

function* suffixes(name) {
  for (let i = 0; ; i = name.indexOf('.', i) + 1) {
    yield name.slice(i);
    if (name.indexOf('.', i) < 0) return;
  }
}

class Filter {
  constructor() {
    this.warnings = [];
    this.listNames = [];
    this.lists = new Map();
    this.deny = new Set();
    this.allowExact = new Set();
    this.allowRules = [];
  }

  // Builds a fresh filter; files that do not exist are treated as empty.
  static load({ blocklists = [], allowFile, denyFile }) {
    const f = new Filter();
    for (const file of blocklists) {
      let lines;
      try {
        lines = fs.readFileSync(file, 'utf8');
      } catch (e) {
        f.warnings.push(`cannot read blocklist ${file}: ${e.code || e.message}`);
        continue;
      }
      const idx = f.listNames.push(path.basename(file)) - 1;
      for (const d of parseList(lines)) f.lists.set(d, idx);
    }
    if (denyFile) {
      for (const d of parseList(readLines(denyFile).join('\n'))) f.deny.add(d);
    }
    if (allowFile) {
      readLines(allowFile).forEach((raw, i) => {
        const line = raw.replace(/\s+#.*$|^\s*#.*$/, '').trim();
        if (!line) return;
        try {
          const rule = parseRule(line);
          if (rule) f.allowRules.push(rule);
          else if (isDomain(normalize(line))) f.allowExact.add(normalize(line));
          else f.warnings.push(`${allowFile}:${i + 1}: ignored "${line}"`);
        } catch (e) {
          f.warnings.push(`${allowFile}:${i + 1}: bad pattern "${line}"`);
        }
      });
    }
    return f;
  }

  get size() {
    return this.lists.size;
  }

  // Precedence: explicit deny file, then allow rules, then the blocklists.
  check(rawName) {
    const name = normalize(rawName);
    if (!name) return { action: 'allow', reason: null };
    for (const s of suffixes(name)) if (this.deny.has(s)) return { action: 'block', reason: 'deny-file' };
    for (const s of suffixes(name)) if (this.allowExact.has(s)) return { action: 'allow', reason: 'allow:' + s };
    for (const r of this.allowRules) if (r.test.test(name)) return { action: 'allow', reason: 'allow:' + r.text };
    for (const s of suffixes(name)) {
      const idx = this.lists.get(s);
      if (idx !== undefined) return { action: 'block', reason: 'list:' + this.listNames[idx] };
    }
    return { action: 'allow', reason: null };
  }
}

function rewrite(file, drop, add) {
  const lines = readLines(file).filter(l => l.trim() !== '');
  const kept = lines.filter(l => normalize(l.replace(/\s+#.*$/, '')) !== drop);
  if (add) kept.push(add);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, kept.join('\n') + (kept.length ? '\n' : ''));
}

// action: "allow" | "block" | "clear". Returns the normalized domain.
function setRule({ allowFile, denyFile }, domain, action) {
  const d = normalize(domain);
  if (!isDomain(d)) throw new Error('not a valid domain: ' + domain);
  if (action === 'allow') {
    rewrite(denyFile, d);
    rewrite(allowFile, d, d);
  } else if (action === 'block') {
    rewrite(allowFile, d);
    rewrite(denyFile, d, d);
  } else if (action === 'clear') {
    rewrite(allowFile, d);
    rewrite(denyFile, d);
  } else {
    throw new Error('unknown action: ' + action);
  }
  return d;
}

module.exports = { Filter, parseList, setRule, isDomain, normalize };
