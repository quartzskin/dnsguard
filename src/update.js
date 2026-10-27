'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { parseList } = require('./blocklist');

// Downloads only the URLs listed in the config; nothing is written if a list parses to zero entries.
async function updateLists(cfg, { dryRun = false, log = console.log, fetchFn = fetch } = {}) {
  if (!cfg.sources.length) {
    log('no "sources" in the config, nothing to download');
    return { ok: 0, failed: 0 };
  }
  let ok = 0, failed = 0;
  for (const s of cfg.sources) {
    try {
      if (dryRun) {
        log(`would fetch ${s.url} -> ${s.file}`);
        continue;
      }
      const res = await fetchFn(s.url, { signal: AbortSignal.timeout(30000) });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const text = await res.text();
      const n = parseList(text).length;
      if (n === 0) throw new Error('no domains found in response, keeping the old file');
      fs.mkdirSync(path.dirname(s.file), { recursive: true });
      const tmp = s.file + '.tmp';
      fs.writeFileSync(tmp, text);
      fs.renameSync(tmp, s.file);
      log(`${s.name || s.url}: ${n} domains -> ${s.file}`);
      ok++;
    } catch (e) {
      log(`${s.name || s.url}: failed (${e.message})`);
      failed++;
    }
  }
  return { ok, failed };
}

module.exports = { updateLists };
