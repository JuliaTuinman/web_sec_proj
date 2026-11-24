// Unit tests for the regex blocklist baseline. No server needed: we drive the
// middleware with a fake req/res, and feed it the parsed body/query shapes that
// Express would hand it. Run: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeMiddleware, findInjections, formatReason } = require('../app/protections/regex');

// Run the middleware once; return {blocked, status, json, nexted}.
function run(mw, { body = {}, query = {} } = {}) {
  const req = { body, query, method: 'POST', originalUrl: '/x' };
  let out = { blocked: false, status: null, json: null, nexted: false };
  const res = { status(c) { out.status = c; return this; }, json(j) { out.blocked = true; out.json = j; return this; } };
  mw(req, res, () => { out.nexted = true; });
  return out;
}

const block = makeMiddleware({ mode: 'block', logger: () => {} });

test('benign body and query pass through', () => {
  assert.ok(run(block, { body: { username: 'alice', password: 'alice123' } }).nexted);
  assert.ok(run(block, { query: { q: 'Laptop' } }).nexted);
  assert.ok(run(block, { query: { category: 'books', maxPrice: '500' } }).nexted);
});

test('benign values with punctuation are not flagged', () => {
  // Real seed passwords / data that contain ! # _ but are not injections.
  for (const pw of ['carol!pw', 'heidi#77', 'frank_pw9', 'gracepw!', 'Adm1n!SuperSecret']) {
    assert.ok(run(block, { body: { username: 'x', password: pw } }).nexted, pw);
  }
});

test('operator keys in the body are blocked', () => {
  const r = run(block, { body: { username: 'admin', password: { $ne: null } } });
  assert.equal(r.status, 403);
  assert.equal(r.json.error, 'blocked');
  assert.match(r.json.detail, /operator key \$ne at body\.password/);
});

test('operator keys injected via the query string are blocked', () => {
  assert.equal(run(block, { query: { q: { $regex: '.*' } } }).status, 403);
  assert.equal(run(block, { query: { username: { $ne: 'x' } } }).status, 403);
  assert.equal(run(block, { query: { q: { $gt: '' } } }).status, 403);
});

test('dotted keys are blocked', () => {
  const r = run(block, { body: { 'a.b': 1 } });
  assert.equal(r.status, 403);
  assert.match(r.json.detail, /dotted key a\.b at body/);
});

test('$where string injection in a value is blocked (what the sanitizer misses)', () => {
  const r = run(block, { query: { category: "x' || true || 'a", maxPrice: '0' } });
  assert.equal(r.status, 403);
  assert.match(r.json.detail, /at query\.category/);
  assert.equal(run(block, { query: { category: 'books', maxPrice: '0 || true' } }).status, 403);
});

test('arrays (?q=a&q=b) are scanned element by element', () => {
  assert.ok(run(block, { query: { q: ['a', 'b'] } }).nexted);
  assert.equal(run(block, { query: { q: ['ok', { $ne: 'x' }] } }).status, 403);
});

test('monitor mode allows the request but records the reasons', () => {
  const lines = [];
  const monitor = makeMiddleware({ mode: 'monitor', logger: (l) => lines.push(l) });
  const r = run(monitor, { body: { username: 'admin', password: { $ne: null } } });
  assert.ok(r.nexted);
  assert.equal(r.blocked, false);
  assert.equal(monitor.stats.flagged, 1);
  assert.ok(lines.some((l) => l.includes('"regex":"flagged"') && l.includes('$ne')));
});

test('hostile __proto__ key does not escape the scan or crash', () => {
  const hostile = JSON.parse('{"__proto__": {"$gt": ""}}');
  const r = run(block, { body: hostile });
  assert.equal(r.status, 403);
  assert.match(r.json.detail, /operator key \$gt/);
});

test('findInjections reports every reason with a path', () => {
  const reasons = findInjections({ body: { password: { $ne: null } }, query: { q: { $regex: '.*' } } });
  const msgs = reasons.map(formatReason);
  assert.ok(msgs.some((m) => /\$ne at body\.password/.test(m)));
  assert.ok(msgs.some((m) => /\$regex at query\.q/.test(m)));
});

test('unknown mode is rejected', () => {
  assert.throws(() => makeMiddleware({ mode: 'nope' }), /unknown mode/);
});
