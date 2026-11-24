// Baselines and payload set, offline: the regex filter is a pure function of the
// request, and sanitizeFilter runs against a fake collection whose findOne() calls
// this.find(), like the driver does. Run: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const qs = require('qs');
const { match } = require('../app/protections/regex');
const { wrapDb } = require('../app/protections/sanitizefilter');
const { ATTACKS, BENIGN, benign } = require('../eval/payloads');

// What Express 4's extended parser hands a middleware for one of our requests.
const parsed = (r) => ({
  query: r.query ? qs.parse(new URLSearchParams(r.query).toString()) : {},
  body: r.json || (r.form ? qs.parse(new URLSearchParams(r.form).toString()) : {}),
});

class FakeCollection {
  constructor(name) { this.collectionName = name; this.calls = []; }
  find(filter) { this.calls.push(filter); return { toArray: async () => [] }; }
  async findOne(filter) { this.find(filter); return null; }
}
const fakeDb = () => wrapDb({ collection: (name) => new FakeCollection(name) });

test('regex filter matches every payload family except the disguised ones', () => {
  for (const a of ATTACKS) {
    const rule = match(parsed(a));
    if (a.family === 'js-evasion') assert.equal(rule, null, `${a.name} is supposed to slip past signatures`);
    else assert.ok(rule, `${a.name} matched no rule`);
  }
  assert.deepEqual(BENIGN.filter((b) => match(parsed(b))).map((b) => b.name), ['search-url']);
});

test('sanitizeFilter wraps an injected operator, keeps normal filters, rejects $where', async () => {
  const users = fakeDb().collection('users');
  await users.findOne({ username: 'admin', password: { $ne: null } });
  assert.deepEqual(users.calls[0], { username: 'admin', password: { $eq: { $ne: null } } });
  const normal = { username: 'alice', password: 'alice123' };
  await users.findOne({ ...normal });
  assert.deepEqual(users.calls[1], normal);

  assert.throws(
    () => fakeDb().collection('products').find({ $where: "this.category == 'books' && this.price <= 500" }),
    (e) => e.mqmBlocked === true && /\$where/.test(e.message)
  );
});

test('payload oracles never count a blocked request as a success', () => {
  const names = [...ATTACKS, ...BENIGN].map((r) => r.name);
  assert.equal(new Set(names).size, names.length, 'duplicate request name');
  for (const a of ATTACKS) {
    assert.equal(a.succeeded(403, { error: 'blocked' }), false, `${a.name} reads a 403 as a success`);
    assert.equal(a.succeeded(500, { error: 'server error' }), false, `${a.name} reads a 500 as a success`);
  }
  for (const b of BENIGN) assert.equal(b.ok(403, { error: 'blocked' }), false, `${b.name} reads a 403 as served`);
});

test('a smaller training fraction is a subset of a larger one', () => {
  assert.deepEqual(benign(0.4), benign(0.8).slice(0, benign(0.4).length));
  assert.equal(benign(1).length, BENIGN.length);
});
