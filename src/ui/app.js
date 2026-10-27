'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const MAX_ROWS = 50;
  const recent = $('recent').tBodies[0];

  function cell(tr, text) {
    const td = tr.insertCell();
    td.textContent = text;
    return td;
  }

  function ruleButton(tr, name, action) {
    const btn = document.createElement('button');
    btn.textContent = action === 'allow' ? 'Allow' : 'Block';
    btn.addEventListener('click', () => setRule(name, action));
    tr.insertCell().append(btn);
  }

  async function setRule(domain, action) {
    try {
      const res = await fetch('/api/rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, action }),
      });
      const body = await res.json();
      $('msg').textContent = res.ok ? `${body.domain} added to the ${action === 'allow' ? 'allow' : 'deny'} file` : body.error;
      if (res.ok) poll();
    } catch {
      $('msg').textContent = 'request failed';
    }
  }

  function result(ev) {
    if (ev.action === 'block') return 'blocked' + (ev.reason ? ` (${ev.reason})` : '');
    return ev.cached ? 'allowed, cached' : 'allowed';
  }

  function addRow(ev) {
    const tr = recent.insertRow(0);
    cell(tr, new Date(ev.ts).toLocaleTimeString());
    cell(tr, ev.client || '-');
    cell(tr, ev.name);
    cell(tr, ev.type);
    const r = cell(tr, result(ev));
    if (ev.action === 'block') r.className = 'block';
    ruleButton(tr, ev.name, ev.action === 'block' ? 'allow' : 'block');
    while (recent.rows.length > MAX_ROWS) recent.deleteRow(-1);
  }

  function fill(tbody, rows, build) {
    tbody.replaceChildren();
    if (!rows.length) {
      const td = tbody.insertRow().insertCell();
      td.colSpan = tbody.parentElement.tHead.rows[0].cells.length;
      td.textContent = 'none yet';
      return;
    }
    for (const r of rows) build(tbody.insertRow(), r);
  }

  function renderStats(s) {
    $('t-total').textContent = s.total;
    $('t-blocked').textContent = s.blocked;
    $('t-cache').textContent = Math.round(s.cacheHitRate * 100) + '%';
    fill($('top-blocked').tBodies[0], s.topBlocked, (tr, b) => {
      cell(tr, b.name);
      cell(tr, b.count);
      ruleButton(tr, b.name, 'allow');
    });
    fill($('top-clients').tBodies[0], s.topClients, (tr, c) => {
      cell(tr, c.client);
      cell(tr, c.count);
    });
  }

  async function poll() {
    try {
      renderStats(await (await fetch('/api/stats')).json());
    } catch {}
  }

  const es = new EventSource('/events');
  es.addEventListener('hello', e => {
    $('conn').textContent = 'live';
    $('conn').className = '';
    const hello = JSON.parse(e.data);
    renderStats(hello.stats);
    recent.replaceChildren();
    hello.recent.forEach(addRow);
  });
  es.onmessage = e => addRow(JSON.parse(e.data));
  es.onerror = () => {
    $('conn').textContent = 'reconnecting';
    $('conn').className = 'down';
  };

  setInterval(poll, 4000);
})();
