'use strict';
const net = require('node:net');

const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, OPT: 41, HTTPS: 65, ANY: 255 };
const TYPE_NAMES = Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [v, k]));
const RCODES = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };

class DnsError extends Error {}

function typeName(t) {
  return TYPE_NAMES[t] || 'TYPE' + t;
}

function typeNumber(s) {
  const up = String(s).toUpperCase();
  if (TYPES[up]) return TYPES[up];
  const m = /^TYPE(\d+)$/.exec(up);
  if (m && +m[1] < 65536) return +m[1];
  throw new DnsError('unknown record type ' + s);
}

// Compression pointers must point strictly backwards, which rules out loops.
function readName(buf, off) {
  const labels = [];
  let pos = off, end = -1, total = 0;
  for (;;) {
    if (pos >= buf.length) throw new DnsError('name runs past end of message');
    const len = buf[pos];
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new DnsError('truncated compression pointer');
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (ptr >= pos) throw new DnsError('compression pointer does not point backwards');
      if (end < 0) end = pos + 2;
      pos = ptr;
      continue;
    }
    if (len & 0xc0) throw new DnsError('unsupported label type');
    if (len === 0) {
      if (end < 0) end = pos + 1;
      break;
    }
    if (pos + 1 + len > buf.length) throw new DnsError('label runs past end of message');
    total += len + 1;
    if (total > 254) throw new DnsError('name too long');
    labels.push(buf.toString('latin1', pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  return { name: labels.join('.'), next: end };
}

function formatIPv6(b) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(b.readUInt16BE(i));
  let bestAt = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) { bestAt = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map(x => x.toString(16));
  if (bestLen < 2) return hex.join(':');
  return hex.slice(0, bestAt).join(':') + '::' + hex.slice(bestAt + bestLen).join(':');
}

function parseIPv6(s) {
  if (!net.isIPv6(s)) throw new DnsError('bad IPv6 address ' + s);
  let v4 = null;
  const m = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (m) {
    const p = m[1].split('.').map(Number);
    v4 = [(p[0] << 8) | p[1], (p[2] << 8) | p[3]].map(x => x.toString(16));
    s = s.slice(0, m.index) + v4.join(':');
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail === undefined ? [] : tail ? tail.split(':') : [];
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const out = Buffer.alloc(16);
  groups.forEach((x, i) => out.writeUInt16BE(parseInt(x, 16), i * 2));
  return out;
}

function decodeRdata(buf, type, off, len) {
  const end = off + len;
  switch (type) {
    case TYPES.A:
      if (len !== 4) throw new DnsError('bad A record length');
      return [...buf.subarray(off, end)].join('.');
    case TYPES.AAAA:
      if (len !== 16) throw new DnsError('bad AAAA record length');
      return formatIPv6(buf.subarray(off, end));
    case TYPES.CNAME:
    case TYPES.NS:
    case TYPES.PTR: {
      const n = readName(buf, off);
      if (n.next > end) throw new DnsError('name overruns record');
      return n.name;
    }
    case TYPES.MX: {
      if (len < 3) throw new DnsError('bad MX record');
      const n = readName(buf, off + 2);
      if (n.next > end) throw new DnsError('name overruns record');
      return { preference: buf.readUInt16BE(off), exchange: n.name };
    }
    case TYPES.TXT: {
      const strings = [];
      for (let p = off; p < end;) {
        const l = buf[p];
        if (p + 1 + l > end) throw new DnsError('TXT string overruns record');
        strings.push(buf.toString('utf8', p + 1, p + 1 + l));
        p += 1 + l;
      }
      return strings;
    }
    case TYPES.HTTPS: {
      if (len < 3) throw new DnsError('bad HTTPS record');
      const n = readName(buf, off + 2);
      if (n.next > end) throw new DnsError('name overruns record');
      const params = [];
      for (let p = n.next; p < end;) {
        if (p + 4 > end) throw new DnsError('truncated HTTPS parameter');
        const key = buf.readUInt16BE(p), vl = buf.readUInt16BE(p + 2);
        if (p + 4 + vl > end) throw new DnsError('HTTPS parameter overruns record');
        params.push({ key, value: Buffer.from(buf.subarray(p + 4, p + 4 + vl)) });
        p += 4 + vl;
      }
      return { priority: buf.readUInt16BE(off), target: n.name || '.', params };
    }
    default:
      return Buffer.from(buf.subarray(off, end));
  }
}

function readRecord(buf, off) {
  const n = readName(buf, off);
  let p = n.next;
  if (p + 10 > buf.length) throw new DnsError('truncated record header');
  const type = buf.readUInt16BE(p), cls = buf.readUInt16BE(p + 2);
  const ttl = buf.readUInt32BE(p + 4), rdlen = buf.readUInt16BE(p + 8);
  const ttlOff = p + 4;
  p += 10;
  if (p + rdlen > buf.length) throw new DnsError('record data runs past end of message');
  return { rec: { name: n.name, type, class: cls, ttl, ttlOff, data: decodeRdata(buf, type, p, rdlen) }, next: p + rdlen };
}

function parse(buf) {
  if (!Buffer.isBuffer(buf)) throw new DnsError('not a buffer');
  if (buf.length < 12) throw new DnsError('message shorter than header');
  const flags = buf.readUInt16BE(2);
  const counts = [4, 6, 8, 10].map(o => buf.readUInt16BE(o));
  const msg = {
    id: buf.readUInt16BE(0),
    qr: flags >> 15 & 1, opcode: flags >> 11 & 15, aa: flags >> 10 & 1,
    tc: flags >> 9 & 1, rd: flags >> 8 & 1, ra: flags >> 7 & 1, rcode: flags & 15,
    questions: [], answers: [], authorities: [], additionals: [],
  };
  // stops absurd counts before looping on them
  if (counts[0] * 5 + (counts[1] + counts[2] + counts[3]) * 11 > buf.length - 12) {
    throw new DnsError('section counts exceed message size');
  }
  let off = 12;
  for (let i = 0; i < counts[0]; i++) {
    const n = readName(buf, off);
    if (n.next + 4 > buf.length) throw new DnsError('truncated question');
    msg.questions.push({ name: n.name, type: buf.readUInt16BE(n.next), class: buf.readUInt16BE(n.next + 2) });
    off = n.next + 4;
  }
  msg.questionEnd = off;
  for (const [i, key] of [[1, 'answers'], [2, 'authorities'], [3, 'additionals']]) {
    for (let k = 0; k < counts[i]; k++) {
      const r = readRecord(buf, off);
      msg[key].push(r.rec);
      off = r.next;
    }
  }
  return msg;
}

class Writer {
  constructor() { this.chunks = []; this.len = 0; this.names = new Map(); }
  push(b) { this.chunks.push(b); this.len += b.length; }
  u16(v) { const b = Buffer.alloc(2); b.writeUInt16BE(v); this.push(b); }
  u32(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v); this.push(b); }
  name(name, compress = true) {
    const labels = name === '' || name === '.' ? [] : name.replace(/\.$/, '').split('.');
    let total = 1;
    for (const l of labels) {
      if (l.length === 0 || l.length > 63) throw new DnsError('bad label length in ' + name);
      total += l.length + 1;
    }
    if (total > 255) throw new DnsError('name too long');
    for (let i = 0; i < labels.length; i++) {
      const key = labels.slice(i).join('.').toLowerCase();
      const at = this.names.get(key);
      if (compress && at !== undefined) { this.u16(0xc000 | at); return; }
      if (this.len < 0x3fff) this.names.set(key, this.len);
      this.push(Buffer.from([labels[i].length]));
      this.push(Buffer.from(labels[i], 'latin1'));
    }
    this.push(Buffer.from([0]));
  }
  done() { return Buffer.concat(this.chunks, this.len); }
}

function writeRdata(w, type, data) {
  if (Buffer.isBuffer(data)) { w.u16(data.length); w.push(data); return; }
  const ph = Buffer.alloc(2);
  w.push(ph);
  const start = w.len;
  switch (type) {
    case TYPES.A: {
      if (!net.isIPv4(data)) throw new DnsError('bad IPv4 address ' + data);
      w.push(Buffer.from(data.split('.').map(Number)));
      break;
    }
    case TYPES.AAAA: w.push(parseIPv6(data)); break;
    case TYPES.CNAME: case TYPES.NS: case TYPES.PTR: w.name(data); break;
    case TYPES.MX: w.u16(data.preference); w.name(data.exchange); break;
    case TYPES.TXT:
      for (const s of Array.isArray(data) ? data : [data]) {
        const b = Buffer.from(s, 'utf8');
        for (let i = 0; i < Math.max(b.length, 1); i += 255) {
          const c = b.subarray(i, i + 255);
          w.push(Buffer.from([c.length]));
          w.push(c);
        }
      }
      break;
    case TYPES.HTTPS:
      w.u16(data.priority);
      w.name(data.target, false);
      for (const p of data.params || []) { w.u16(p.key); w.u16(p.value.length); w.push(p.value); }
      break;
    default: throw new DnsError('cannot encode record type ' + typeName(type));
  }
  const size = w.len - start;
  if (size > 0xffff) throw new DnsError('record too large');
  ph.writeUInt16BE(size);
}

function build(msg) {
  const w = new Writer();
  const flags = (msg.qr ? 0x8000 : 0) | ((msg.opcode || 0) << 11) | (msg.aa ? 0x400 : 0) |
    (msg.tc ? 0x200 : 0) | (msg.rd ? 0x100 : 0) | (msg.ra ? 0x80 : 0) | ((msg.rcode || 0) & 15);
  const secs = [msg.answers || [], msg.authorities || [], msg.additionals || []];
  w.u16(msg.id & 0xffff);
  w.u16(flags);
  w.u16((msg.questions || []).length);
  for (const s of secs) w.u16(s.length);
  for (const q of msg.questions || []) {
    w.name(q.name);
    w.u16(q.type);
    w.u16(q.class || 1);
  }
  for (const s of secs) {
    for (const r of s) {
      w.name(r.name);
      w.u16(r.type);
      w.u16(r.class || 1);
      w.u32(r.ttl >>> 0);
      writeRdata(w, r.type, r.data);
    }
  }
  return w.done();
}

function reply(query, rcode, answers = []) {
  return build({
    id: query.id, qr: 1, opcode: query.opcode, rd: query.rd, ra: 1, rcode,
    questions: query.questions, answers,
  });
}

function truncate(buf, msg) {
  const out = Buffer.from(buf.subarray(0, msg.questionEnd));
  out.writeUInt16BE(out.readUInt16BE(2) | 0x200, 2);
  out.fill(0, 6, 12);
  return out;
}

function minTtl(msg) {
  let min = Infinity;
  for (const r of [...msg.answers, ...msg.authorities]) if (r.ttl < min) min = r.ttl;
  return min;
}

// Rewrite every TTL in place (OPT pseudo-records carry flags there, so they are skipped).
function ageTtls(buf, msg, seconds) {
  const out = Buffer.from(buf);
  for (const r of [...msg.answers, ...msg.authorities, ...msg.additionals]) {
    if (r.type === TYPES.OPT) continue;
    out.writeUInt32BE(Math.max(1, r.ttl - seconds), r.ttlOff);
  }
  return out;
}

module.exports = {
  TYPES, RCODES, DnsError, typeName, typeNumber, parse, build, reply, truncate, minTtl, ageTtls, readName,
};
