// Unit tests for MQM. No MongoDB needed: a fake collection mimics the driver API
// (including findOne() calling this.find() internally, like mongodb v6 does).
// Run: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createGuard } = require('../app/protections/mqm/guard');
const { shapeOf, canonical } = require('../app/protections/mqm/shape');
const { jsStructure } = require('../app/protections/mqm/js-structure');

class FakeCollection {
  constructor(name) { this.collectionName = name; this.calls = []; }
  find(filter) { this.calls.push(filter); return { toArray: async () => [] }; }
  async findOne(filter) { this.find(filter); return null; }
  async updateOne() { return { acknowledged: true }; }
}
const fakeDb = () => ({ collection: (name) => new FakeCollection(name) });

function guard(mode, extra = {}) {
  return createGuard({ mode, persist: false, logger: () => {}, ...extra });
}

// Same site, as the routes do it: one line per query.
const login = (db, username, password) => db.collection('users').findOne({ username, password });
const search = (db, q) => db.collection('products').find({ name: q });
const filter = (db, category, maxPrice) =>
  db.collection('products').find({ $where: `this.category == '${category}' && this.price <= ${maxPrice || 1e9}` });

// Learn with one guard, then enforce with a second guard sharing the learned model.
function trained(trainFn, extra = {}) {
  const g = guard('learn');
  trainFn(g.wrapDb(fakeDb()));
  const e = guard('enforce', extra);
  e.model.sites = g.model.sites;
  return e.wrapDb(fakeDb());
}

const blocked = async (fn) => {
  try { await fn(); } catch (e) { if (e.mqmBlocked) return e; throw e; }
  assert.fail('expected the query to be blocked');
};

test('shape drops values but keeps fields, types and operators', () => {
  assert.equal(canonical(shapeOf({ username: 'alice', password: 'x' })), '{"password":"string","username":"string"}');
  assert.equal(canonical(shapeOf({ password: { $ne: null } })), '{"password":{"$ne":"null"}}');
  assert.equal(canonical(shapeOf({ t: { $in: ['a', 'b', 'c'] } })), canonical(shapeOf({ t: { $in: ['z'] } })));
  assert.equal(canonical(shapeOf({ b: 1, a: 2 })), canonical(shapeOf({ a: 3, b: 4 })));
});

test('JS structure ignores literal values but not injected code', () => {
  const tpl = (c, p) => `this.category == '${c}' && this.price <= ${p}`;
  assert.equal(jsStructure(tpl('books', 500)), 'this . category == STR && this . price <= NUM');
  assert.equal(jsStructure(tpl('home & garden', 1e9)), jsStructure(tpl('books', 500)));
  assert.notEqual(jsStructure(tpl("x' || true || 'a", 0)), jsStructure(tpl('books', 500)));
  assert.notEqual(jsStructure(tpl("books' //", 500)), jsStructure(tpl('books', 500)));
  assert.notEqual(jsStructure(tpl('books', '0 || true')), jsStructure(tpl('books', 500)));
  assert.equal(jsStructure("'it\\'s' == x"), 'STR == x'); // escaped quote stays inside the string
  assert.equal(jsStructure("'oops"), 'STR!');
});

test('login: operator injection is blocked, normal logins pass', async () => {
  const db = trained((db) => { login(db, 'alice', 'alice123'); login(db, 'bob', 'pw'); });
  await login(db, 'carol', 'whatever'); // unseen values, same shape
  const err = await blocked(() => login(db, 'admin', { $ne: null }));
  assert.match(err.message, /new operator \$ne at filter\.password/);
  assert.match(err.message, /object where string expected at filter\.password/);
  assert.equal(err.mqm.site.split('@')[0], 'users.findOne');
});

test('search/profile: $regex and $ne injection via query-string objects are blocked', async () => {
  const db = trained((db) => { search(db, 'Laptop'); });
  search(db, 'Desk Lamp');
  await blocked(() => search(db, { $regex: '.*' }));
  await blocked(() => search(db, { $ne: 'x' }));
  await blocked(() => search(db, ['a', 'b'])); // ?q=a&q=b
});

test('$where: data passes, JS injection is blocked', async () => {
  const db = trained((db) => { filter(db, 'books', '500'); filter(db, 'electronics', undefined); });
  filter(db, 'clothing', '20');
  const err = await blocked(() => filter(db, "x' || true || 'a", '0'));
  assert.match(err.message, /JavaScript structure changed/);
  await blocked(() => filter(db, 'books', '0 || true'));
  await blocked(() => filter(db, "books'; while(true){}; '", '1'));
});

test('operators the app itself uses stay allowed (precise, not blanket)', async () => {
  const regexSearch = (db, q, extra) => db.collection('products').find({ name: { $regex: q, $options: 'i' }, ...extra });
  const db = trained((db) => { regexSearch(db, '^lap'); });
  regexSearch(db, 'desk'); // legitimate $regex, new pattern: allowed
  const err = await blocked(() => regexSearch(db, 'x', { $or: [{ role: 'admin' }] }));
  assert.match(err.message, /new operator \$or/);
});

test('sites are keyed by call site: same collection+method on another line is separate', async () => {
  const db = trained((db) => { login(db, 'alice', 'pw'); });
  // same collection and method, different line in the code, never learned:
  const err = await blocked(() => db.collection('users').findOne({ username: 'alice', password: 'pw' }));
  assert.match(err.message, /never seen in learn mode/);
});

test('collection keying and MQM_UNKNOWN=allow loosen the policy', async () => {
  const g = guard('learn', { siteKeying: 'collection' });
  login(g.wrapDb(fakeDb()), 'alice', 'pw');
  const e = guard('enforce', { siteKeying: 'collection' });
  e.model.sites = g.model.sites;
  const db = e.wrapDb(fakeDb());
  await db.collection('users').findOne({ username: 'x', password: 'y' }); // other line, same key
  await blocked(() => db.collection('users').findOne({ username: 'x', password: { $gt: '' } }));

  const open = trained(() => {}, { unknownSite: 'allow' });
  await open.collection('users').findOne({ anything: { $ne: 1 } });
});

test('driver-internal calls (findOne -> find) are checked once', async () => {
  const g = guard('learn');
  const db = g.wrapDb(fakeDb());
  await login(db, 'alice', 'pw');
  assert.equal(g.stats.checked, 1);
  assert.deepEqual([...g.model.sites.keys()].map((s) => s.split('@')[0]), ['users.findOne']);
});

test('update documents are part of the shape', async () => {
  const setName = (db, id, name) => db.collection('users').updateOne({ username: id }, { $set: { name } });
  const db = trained((db) => { setName(db, 'alice', 'Alice'); });
  await setName(db, 'bob', 'Bob');
  await blocked(() => setName(db, 'bob', { $gt: '' }));
});

test('monitor mode flags but does not block', async () => {
  const g = guard('learn');
  login(g.wrapDb(fakeDb()), 'alice', 'pw');
  const lines = [];
  const m = guard('monitor', { logger: (l) => lines.push(l) });
  m.model.sites = g.model.sites;
  await login(m.wrapDb(fakeDb()), 'admin', { $ne: null });
  assert.equal(m.stats.flagged, 1);
  assert.ok(lines.some((l) => l.includes('"mqm":"flagged"')));
});

test('model persists to disk and is reloaded for enforce mode', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mqm-'));
  const modelPath = path.join(dir, 'model.json');
  const logPath = path.join(dir, 'blocked.jsonl');
  const g = createGuard({ mode: 'learn', modelPath, logger: () => {} });
  await login(g.wrapDb(fakeDb()), 'alice', 'pw');
  assert.ok(fs.existsSync(modelPath));

  const e = createGuard({ mode: 'enforce', modelPath, logPath, logger: () => {} });
  const db = e.wrapDb(fakeDb());
  await login(db, 'bob', 'pw2');
  await blocked(() => login(db, 'admin', { $ne: null }));
  const logged = fs.readFileSync(logPath, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(logged.length, 1);
  assert.equal(logged[0].mqm, 'blocked');
  fs.rmSync(dir, { recursive: true });
});

test('hostile keys do not confuse shapes or diffs', async () => {
  const db = trained((db) => { login(db, 'alice', 'pw'); });
  await blocked(() => login(db, { __proto__: { $ne: 1 } }, 'pw'));
  await blocked(() => login(db, { toString: 'x' }, 'pw'));
  await blocked(() => login(db, JSON.parse('{"__proto__": {"$gt": ""}}'), 'pw'));
});

test('plain objects posing as BSON values stay containers', () => {
  const { ObjectId } = require('mongodb');
  assert.equal(shapeOf(new ObjectId()), 'objectId');
  assert.equal(canonical(shapeOf({ _bsontype: 'ObjectId', $ne: 1 })), '{"$ne":"number","_bsontype":"string"}');
});
