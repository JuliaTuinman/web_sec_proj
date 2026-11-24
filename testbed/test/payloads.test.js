// Tests for the payload/baseline sets and the traffic generator helpers. No server:
// we check the data's integrity, the oracles, the query encoding, and how the regex
// baseline classifies every payload. Run: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const { endpoints, allCases } = require('../traffic/payloads');
const { encodeQuery, classify, summarize } = require('../traffic/generate');
const { findInjections } = require('../app/protections/regex');

test('every endpoint has benign baseline and attack payloads', () => {
  for (const [name, ep] of Object.entries(endpoints)) {
    assert.ok(ep.cases.some((c) => c.kind === 'benign'), `${name} has benign`);
    assert.ok(ep.cases.some((c) => c.kind === 'attack'), `${name} has attacks`);
    assert.equal(typeof ep.benignOk, 'function', `${name} benignOk`);
    for (const c of ep.cases) {
      if (c.kind === 'attack') assert.equal(typeof c.exploited, 'function', `${name}/${c.name} exploited`);
    }
  }
});

test('query objects are encoded into the bracket notation qs parses back', () => {
  assert.equal(encodeQuery({ q: 'Laptop' }), '?q=Laptop');
  assert.equal(encodeQuery({ q: { $regex: '.*' } }), '?q[$regex]=.*');
  assert.equal(encodeQuery({ username: { $ne: 'x' } }), '?username[$ne]=x');
  assert.equal(encodeQuery({ q: ['a', 'b'] }), '?q=a&q=b');
  assert.equal(encodeQuery({ category: 'books', maxPrice: '500' }), '?category=books&maxPrice=500');
  assert.equal(encodeQuery(), '');
});

test('oracles judge responses by content', () => {
  const login = endpoints.login;
  assert.ok(login.benignOk({ status: 200, body: { success: true, role: 'user' } }));
  assert.ok(!login.benignOk({ status: 401, body: { success: false } }));
  const bypass = login.cases.find((c) => c.name === 'password $ne null');
  assert.ok(bypass.exploited({ status: 200, body: { success: true, role: 'admin' } }));
  assert.ok(!bypass.exploited({ status: 403, body: { error: 'blocked' } }));

  const dump = endpoints.search.cases.find((c) => c.name === 'q[$regex]=.*');
  assert.ok(dump.exploited({ status: 200, body: { count: 26 } }));
  assert.ok(!dump.exploited({ status: 200, body: { count: 0 } })); // sanitizer neutralized -> stopped
  assert.ok(endpoints.search.benignOk({ status: 200, body: { count: 1 } }));
  assert.ok(!endpoints.search.benignOk({ status: 200, body: { count: 26 } }));
});

test('classify maps oracle + kind to an outcome', () => {
  const benign = { kind: 'benign', ok: () => true };
  const benignBroken = { kind: 'benign', ok: () => false };
  const attackStopped = { kind: 'attack', ok: () => false };
  const attackMissed = { kind: 'attack', ok: () => true };
  assert.equal(classify(benign, {}), 'served');
  assert.equal(classify(benignBroken, {}), 'FALSE-POS');
  assert.equal(classify(attackStopped, {}), 'stopped');
  assert.equal(classify(attackMissed, {}), 'EXPLOITED');
});

test('summarize tallies benign and attack outcomes', () => {
  const s = summarize([
    { kind: 'benign', outcome: 'served' },
    { kind: 'benign', outcome: 'FALSE-POS' },
    { kind: 'attack', outcome: 'stopped' },
    { kind: 'attack', outcome: 'EXPLOITED' },
  ]);
  assert.deepEqual(s.benign, { total: 2, served: 1, falsePos: 1 });
  assert.deepEqual(s.attack, { total: 2, stopped: 1, exploited: 1 });
});

// The payloads are the contract the regex baseline is measured against.
test('regex baseline blocks every non-evasion attack payload', () => {
  for (const c of allCases().filter((c) => c.kind === 'attack' && !c.evasion)) {
    assert.ok(findInjections(c).length > 0, `missed attack ${c.endpoint}/${c.name}`);
  }
});

// Evasion payloads exploit the app using only characters no signature matches. They
// are labeled so the harness can measure the blocklist's miss rate; assert they slip by.
test('regex baseline misses evasion attacks (documented weakness)', () => {
  const evasions = allCases().filter((c) => c.kind === 'attack' && c.evasion);
  assert.ok(evasions.length > 0);
  for (const c of evasions) {
    assert.deepEqual(findInjections(c), [], `evasion unexpectedly caught: ${c.endpoint}/${c.name}`);
  }
});

test('MQM JS-structure check catches the $where evasions the regex misses', () => {
  const { jsStructure } = require('../app/protections/mqm/js-structure');
  const where = (q) => `this.category == '${q.category}' && this.price <= ${q.maxPrice || 1e9}`;
  const learned = jsStructure(where({ category: 'books', maxPrice: '500' }));
  for (const c of allCases().filter((c) => c.endpoint === 'filter' && c.evasion)) {
    assert.notEqual(jsStructure(where(c.query)), learned, `MQM would miss ${c.name}`);
  }
});

test('regex baseline passes clean benign traffic (no false positives)', () => {
  for (const c of allCases().filter((c) => c.kind === 'benign' && !c.edge)) {
    assert.deepEqual(findInjections(c), [], `false positive on ${c.endpoint}/${c.name}`);
  }
});

// The blocklist is blunt: benign input that merely contains injection-like characters
// trips it. These cases are labeled `edge` precisely to document that false-positive
// behavior (and to let the harness measure its rate), so assert it holds.
test('regex baseline false-positives on edge benign traffic (documented weakness)', () => {
  for (const c of allCases().filter((c) => c.kind === 'benign' && c.edge)) {
    assert.ok(findInjections(c).length > 0, `expected edge case to trip the blocklist: ${c.endpoint}/${c.name}`);
  }
});
