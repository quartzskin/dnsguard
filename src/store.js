'use strict';
const { DatabaseSync } = require('node:sqlite');

class Store {
  constructor(file, { privacy = false, retentionDays = 30, maxLogRows = 100000 } = {}) {
    this.privacy = privacy;
    this.retentionDays = retentionDays;
    this.maxLogRows = maxLogRows;
    this.db = new DatabaseSync(file);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS queries (
        id INTEGER PRIMARY KEY,
        ts INTEGER NOT NULL,
        client TEXT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        action TEXT NOT NULL,
        reason TEXT,
        cached INTEGER NOT NULL DEFAULT 0,
        ms INTEGER,
        rcode INTEGER
      );
      CREATE INDEX IF NOT EXISTS queries_ts ON queries(ts);
      CREATE INDEX IF NOT EXISTS queries_name ON queries(name);
    `);
    this.insert = this.db.prepare(
      'INSERT INTO queries (ts, client, name, type, action, reason, cached, ms, rcode) VALUES (?,?,?,?,?,?,?,?,?)');
    this.writes = 0;
    this.prune();
  }

  log(q) {
    this.insert.run(q.ts, this.privacy ? null : q.client ?? null, q.name, q.type, q.action,
      q.reason ?? null, q.cached ? 1 : 0, q.ms ?? null, q.rcode ?? null);
    if (++this.writes % 500 === 0) this.prune();
  }

  prune() {
    if (this.retentionDays > 0) {
      this.db.prepare('DELETE FROM queries WHERE ts < ?').run(Date.now() - this.retentionDays * 86400000);
    }
    if (this.maxLogRows > 0) {
      this.db.prepare('DELETE FROM queries WHERE id <= (SELECT MAX(id) FROM queries) - ?').run(this.maxLogRows);
    }
  }

  recent(limit = 50) {
    return this.db.prepare('SELECT ts, client, name, type, action, reason, cached, ms, rcode FROM queries ORDER BY id DESC LIMIT ?')
      .all(limit).reverse().map(r => ({ ...r, cached: !!r.cached }));
  }

  stats({ since = 0, top = 10 } = {}) {
    const one = (sql, ...a) => this.db.prepare(sql).get(...a);
    const rows = (sql, ...a) => this.db.prepare(sql).all(...a).map(r => ({ ...r }));
    const total = one('SELECT COUNT(*) n FROM queries WHERE ts >= ?', since).n;
    const blocked = one("SELECT COUNT(*) n FROM queries WHERE ts >= ? AND action = 'block'", since).n;
    const cached = one("SELECT COUNT(*) n FROM queries WHERE ts >= ? AND cached = 1 AND action = 'allow'", since).n;
    const answerable = total - blocked;
    return {
      total, blocked, allowed: answerable, cached,
      cacheHitRate: answerable ? cached / answerable : 0,
      topBlocked: rows("SELECT name, COUNT(*) count FROM queries WHERE ts >= ? AND action = 'block' GROUP BY name ORDER BY count DESC, name LIMIT ?", since, top),
      topDomains: rows('SELECT name, COUNT(*) count FROM queries WHERE ts >= ? GROUP BY name ORDER BY count DESC, name LIMIT ?', since, top),
      topClients: rows('SELECT client, COUNT(*) count FROM queries WHERE ts >= ? AND client IS NOT NULL GROUP BY client ORDER BY count DESC LIMIT ?', since, top),
    };
  }

  close() {
    this.db.close();
  }
}

module.exports = { Store };
