'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('../src/dns');

const { TYPES, DnsError } = dns;

function sample() {
  return dns.build({
    id: 0xbeef, qr: 1, rd: 1, ra: 1,
    questions: [{ name: 'www.example.com', type: TYPES.A, class: 1 }],
    answers: [
      { name: 'www.example.com', type: TYPES.CNAME, ttl: 300, data: 'edge.example.com' },
      { name: 'edge.example.com', type: TYPES.A, ttl: 60, data: '192.0.2.7' },
      { name: 'edge.example.com', type: TYPES.AAAA, ttl: 60, data: '2001:db8::1' },
      { name: 'example.com', type: TYPES.TXT, ttl: 10, data: ['v=spf1 -all', 'second'] },
      { name: 'example.com', type: TYPES.HTTPS, ttl: 10, data: { priority: 1, target: '.', params: [{ key: 1, value: Buffer.from([2, 104, 50]) }] } },
    ],
  });
}

test('round trip of all supported record types', () => {
  const m = dns.parse(sample());
  assert.equal(m.id, 0xbeef);
  assert.equal(m.qr, 1);
  assert.deepEqual(m.questions[0], { name: 'www.example.com', type: 1, class: 1 });
  assert.equal(m.answers[0].data, 'edge.example.com');
  assert.equal(m.answers[1].data, '192.0.2.7');
  assert.equal(m.answers[2].data, '2001:db8::1');
  assert.deepEqual(m.answers[3].data, ['v=spf1 -all', 'second']);
  assert.equal(m.answers[4].data.priority, 1);
  assert.equal(m.answers[4].data.target, '.');
  assert.deepEqual([...m.answers[4].data.params[0].value], [2, 104, 50]);
});

test('names are compressed on build and followed on parse', () => {
  const buf = sample();
  const plain = Buffer.byteLength('www.example.com') * 3;
  assert.ok(buf.length < 12 + plain + 150, 'compression should shrink the message');
  assert.ok(buf.includes(Buffer.from([0xc0, 0x0c])), 'expected a pointer to the question name');
});

test('IPv6 formatting', () => {
  for (const a of ['::', '::1', '2001:db8::1', 'fe80::1:2', '1:2:3:4:5:6:7:8', '1::8']) {
    const m = dns.parse(dns.build({ id: 1, questions: [], answers: [{ name: 'a.test', type: TYPES.AAAA, ttl: 1, data: a }] }));
    assert.equal(m.answers[0].data, a);
  }
  assert.throws(() => dns.build({ id: 1, answers: [{ name: 'a.test', type: TYPES.AAAA, ttl: 1, data: 'nope' }] }), DnsError);
});

test('compression pointer loops and forward pointers are rejected', () => {
  const head = Buffer.from('000100000001000000000000', 'hex');
  const selfPtr = Buffer.concat([head, Buffer.from([0xc0, 12, 0, 1, 0, 1])]);
  assert.throws(() => dns.parse(selfPtr), DnsError);
  const fwd = Buffer.concat([head, Buffer.from([0xc0, 0x20, 0, 1, 0, 1])]);
  assert.throws(() => dns.parse(fwd), DnsError);
  const ab = Buffer.concat([head, Buffer.from([1, 0x61, 0xc0, 12, 0, 1, 0, 1])]);
  assert.throws(() => dns.parse(ab), DnsError);
});

test('every truncation of a valid message fails cleanly', () => {
  const buf = sample();
  for (let n = 0; n < buf.length; n++) {
    assert.throws(() => dns.parse(buf.subarray(0, n)), DnsError, `length ${n}`);
  }
});

test('oversized label, name and counts are rejected', () => {
  const longLabel = Buffer.concat([Buffer.from('000100000001000000000000', 'hex'), Buffer.from([64]), Buffer.alloc(64, 0x61), Buffer.from([0, 0, 1, 0, 1])]);
  assert.throws(() => dns.parse(longLabel), DnsError);
  assert.throws(() => dns.build({ id: 1, questions: [{ name: 'a'.repeat(64) + '.test', type: 1 }] }), DnsError);
  assert.throws(() => dns.build({ id: 1, questions: [{ name: Array(60).fill('abcd').join('.'), type: 1 }] }), DnsError);
  assert.throws(() => dns.build({ id: 1, questions: [{ name: 'a..b', type: 1 }] }), DnsError);
  const lies = Buffer.from('0001000000ff00ff00ff00ff', 'hex');
  assert.throws(() => dns.parse(lies), DnsError);
});

test('record data length that lies is rejected', () => {
  const buf = sample();
  const m = dns.parse(buf);
  // first answer's rdlength sits right before its rdata; make it huge
  const bad = Buffer.from(buf);
  bad.writeUInt16BE(0xfff0, m.answers[0].ttlOff + 4);
  assert.throws(() => dns.parse(bad), DnsError);
  const badA = dns.build({ id: 1, answers: [{ name: 'a.test', type: TYPES.A, ttl: 1, data: Buffer.from([1, 2, 3]) }] });
  assert.throws(() => dns.parse(badA), DnsError);
});

test('fuzz: random bytes only ever throw DnsError', () => {
  let seed = 12345;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let i = 0; i < 4000; i++) {
    const buf = Buffer.alloc(Math.floor(rnd() * 120));
    for (let j = 0; j < buf.length; j++) buf[j] = Math.floor(rnd() * 256);
    try { dns.parse(buf); } catch (e) { assert.ok(e instanceof DnsError, e.stack); }
  }
});

test('fuzz: mutated valid messages only ever throw DnsError', () => {
  const base = sample();
  let seed = 99;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let i = 0; i < 6000; i++) {
    const buf = Buffer.from(base);
    for (let k = 0; k < 1 + Math.floor(rnd() * 4); k++) buf[Math.floor(rnd() * buf.length)] = Math.floor(rnd() * 256);
    try { dns.parse(buf); } catch (e) { assert.ok(e instanceof DnsError, e.stack); }
  }
});

test('ageTtls lowers TTLs but not below 1, and minTtl sees them', () => {
  const buf = sample();
  const m = dns.parse(buf);
  assert.equal(dns.minTtl(m), 10);
  const aged = dns.parse(dns.ageTtls(buf, m, 30));
  assert.deepEqual(aged.answers.map(a => a.ttl), [270, 30, 30, 1, 1]);
});

test('truncate keeps header and question with TC set', () => {
  const buf = sample();
  const t = dns.parse(dns.truncate(buf, dns.parse(buf)));
  assert.equal(t.tc, 1);
  assert.equal(t.answers.length, 0);
  assert.equal(t.questions.length, 1);
});

test('type names', () => {
  assert.equal(dns.typeName(65), 'HTTPS');
  assert.equal(dns.typeName(999), 'TYPE999');
  assert.equal(dns.typeNumber('aaaa'), 28);
  assert.equal(dns.typeNumber('type99'), 99);
  assert.throws(() => dns.typeNumber('bogus'), DnsError);
});
