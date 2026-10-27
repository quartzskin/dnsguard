'use strict';
const dgram = require('node:dgram');
const net = require('node:net');
const { EventEmitter } = require('node:events');
const dns = require('./dns');
const { isLoopback } = require('./config');

const { TYPES, RCODES } = dns;
const MAX_CACHE_TTL = 3600;
const NEG_TTL = 30;

class TtlCache {
  constructor(max) {
    this.max = max;
    this.map = new Map();
  }

  get(key) {
    const e = this.map.get(key);
    if (!e) return null;
    const age = Math.floor((Date.now() - e.at) / 1000);
    if (age >= e.ttl) { this.map.delete(key); return null; }
    return { buf: e.buf, msg: e.msg, age };
  }

  set(key, buf, msg, ttl) {
    if (this.max <= 0 || ttl <= 0) return;
    this.map.delete(key);
    this.map.set(key, { buf, msg, ttl, at: Date.now() });
    if (this.map.size > this.max) this.map.delete(this.map.keys().next().value);
  }
}

function sameQuestion(a, b) {
  try {
    const qa = dns.parse(a).questions, qb = dns.parse(b).questions;
    return qa.length === 1 && qb.length === 1 && qa[0].name.toLowerCase() === qb[0].name.toLowerCase() &&
      qa[0].type === qb[0].type && qa[0].class === qb[0].class;
  } catch { return false; }
}

function udpQuery(addr, buf, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket(net.isIPv6(addr.host) ? 'udp6' : 'udp4');
    const done = (fn, v) => { clearTimeout(timer); try { sock.close(); } catch {} fn(v); };
    const timer = setTimeout(() => done(reject, new Error('upstream timeout')), timeoutMs);
    sock.on('error', e => done(reject, e));
    sock.on('message', (m, r) => {
      if (r.port !== addr.port || r.address.toLowerCase() !== addr.host.toLowerCase()) return;
      if (m.length < 12 || m.readUInt16BE(0) !== buf.readUInt16BE(0) || !sameQuestion(buf, m)) return;
      done(resolve, m);
    });
    sock.send(buf, addr.port, addr.host, e => e && done(reject, e));
  });
}

function tcpQuery(addr, buf, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(addr.port, addr.host);
    const chunks = [];
    let have = 0;
    const done = (fn, v) => { clearTimeout(timer); sock.destroy(); fn(v); };
    const timer = setTimeout(() => done(reject, new Error('upstream tcp timeout')), timeoutMs);
    sock.on('error', e => done(reject, e));
    sock.on('close', () => done(reject, new Error('upstream closed connection')));
    sock.on('connect', () => {
      const head = Buffer.alloc(2);
      head.writeUInt16BE(buf.length);
      sock.write(Buffer.concat([head, buf]));
    });
    sock.on('data', d => {
      chunks.push(d);
      have += d.length;
      const all = Buffer.concat(chunks, have);
      if (all.length >= 2 && all.length >= 2 + all.readUInt16BE(0)) {
        done(resolve, all.subarray(2, 2 + all.readUInt16BE(0)));
      }
    });
  });
}

class DnsGuard extends EventEmitter {
  constructor(cfg, { filter, store } = {}) {
    super();
    this.cfg = cfg;
    this.filter = filter;
    this.store = store;
    this.cache = new TtlCache(cfg.cacheSize);
    this.udp = null;
    this.tcp = null;
    this.port = null;
  }

  async start() {
    const { listen } = this.cfg;
    if (!isLoopback(listen) && !this.cfg.allowOpen) {
      throw new Error(`refusing to listen on ${listen}: that exposes an open resolver; pass --allow-open to do it anyway`);
    }
    this.udp = dgram.createSocket(net.isIPv6(listen) ? 'udp6' : 'udp4');
    await new Promise((resolve, reject) => {
      this.udp.once('error', reject);
      this.udp.bind(this.cfg.port, listen, resolve);
    });
    this.port = this.udp.address().port;
    this.udp.on('error', e => this.emit('error', e));
    this.udp.on('message', async (msg, rinfo) => {
      const out = await this.handle(msg, rinfo.address, 'udp').catch(() => null);
      if (out) this.udp.send(out, rinfo.port, rinfo.address, () => {});
    });
    this.tcp = net.createServer(sock => this.onTcp(sock));
    await new Promise((resolve, reject) => {
      this.tcp.once('error', reject);
      this.tcp.listen(this.port, listen, resolve);
    }).catch(e => { this.udp.close(); throw e; });
    this.tcp.on('error', e => this.emit('error', e));
  }

  onTcp(sock) {
    let buf = Buffer.alloc(0);
    sock.setTimeout(10000, () => sock.destroy());
    sock.on('error', () => sock.destroy());
    sock.on('data', async d => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const len = buf.readUInt16BE(0);
        const msg = buf.subarray(2, 2 + len);
        buf = buf.subarray(2 + len);
        const out = await this.handle(Buffer.from(msg), sock.remoteAddress, 'tcp').catch(() => null);
        if (!out || sock.destroyed) continue;
        const head = Buffer.alloc(2);
        head.writeUInt16BE(out.length);
        sock.write(Buffer.concat([head, out]));
      }
    });
  }

  async stop() {
    await Promise.all([
      new Promise(r => this.udp ? this.udp.close(r) : r()),
      new Promise(r => this.tcp ? this.tcp.close(r) : r()),
    ]);
  }

  record(ev) {
    if (this.cfg.privacy) ev.client = null;
    if (this.store) {
      try { this.store.log(ev); } catch (e) { this.emit('warning', e); }
    }
    this.emit('query', ev);
  }

  blockedReply(q) {
    const name = q.questions[0];
    if (this.cfg.blockMode === 'nxdomain') return dns.reply(q, RCODES.NXDOMAIN);
    if (name.type === TYPES.A) return dns.reply(q, RCODES.NOERROR, [{ name: name.name, type: TYPES.A, ttl: 60, data: '0.0.0.0' }]);
    if (name.type === TYPES.AAAA) return dns.reply(q, RCODES.NOERROR, [{ name: name.name, type: TYPES.AAAA, ttl: 60, data: '::' }]);
    return dns.reply(q, RCODES.NOERROR);
  }

  async forward(buf) {
    const { upstreamAddr: addr, upstreamTimeoutMs: t } = this.cfg;
    let resp;
    try {
      resp = await udpQuery(addr, buf, t);
    } catch (e) {
      if (e.message !== 'upstream timeout') throw e;
      resp = await udpQuery(addr, buf, t);
    }
    if (resp.length >= 4 && (resp.readUInt16BE(2) & 0x200)) resp = await tcpQuery(addr, buf, t);
    return resp;
  }

  async handle(buf, client, proto) {
    const t0 = Date.now();
    let q;
    try {
      q = dns.parse(buf);
    } catch {
      if (buf.length < 12) return null;
      const r = Buffer.alloc(12);
      r.writeUInt16BE(buf.readUInt16BE(0), 0);
      r.writeUInt16BE(0x8000 | 0x80 | RCODES.FORMERR, 2);
      return r;
    }
    if (q.qr) return null;
    if (q.opcode !== 0) return dns.reply(q, RCODES.NOTIMP);
    if (q.questions.length !== 1) return dns.reply(q, RCODES.FORMERR);

    const qn = q.questions[0];
    const ev = { ts: t0, client, name: qn.name.toLowerCase() || '.', type: dns.typeName(qn.type), action: 'allow', reason: null, cached: false };
    const verdict = this.filter ? this.filter.check(qn.name) : { action: 'allow', reason: null };
    ev.action = verdict.action;
    ev.reason = verdict.reason;

    let out;
    if (verdict.action === 'block') {
      out = this.blockedReply(q);
      ev.rcode = out.readUInt16BE(2) & 15;
    } else {
      const key = `${ev.name}|${qn.type}|${qn.class}`;
      const hit = this.cache.get(key);
      if (hit) {
        out = dns.ageTtls(hit.buf, hit.msg, hit.age);
        out.writeUInt16BE(q.id, 0);
        ev.cached = true;
      } else {
        try {
          out = await this.forward(buf);
          const r = dns.parse(out);
          if (!r.tc && (r.rcode === RCODES.NOERROR || r.rcode === RCODES.NXDOMAIN)) {
            const ttl = Math.min(dns.minTtl(r), MAX_CACHE_TTL);
            this.cache.set(key, out, r, Number.isFinite(ttl) ? ttl : NEG_TTL);
          }
        } catch {
          out = dns.reply(q, RCODES.SERVFAIL);
        }
      }
      ev.rcode = out.readUInt16BE(2) & 15;
    }
    ev.ms = Date.now() - t0;
    this.record(ev);

    if (proto === 'udp') {
      const opt = q.additionals.find(r => r.type === TYPES.OPT);
      const limit = opt ? Math.max(512, Math.min(opt.class, 1232)) : 512;
      if (out.length > limit) {
        try { return dns.truncate(out, dns.parse(out)); } catch { return dns.reply(q, RCODES.SERVFAIL); }
      }
    }
    return out;
  }
}

module.exports = { DnsGuard, TtlCache, udpQuery, tcpQuery };
