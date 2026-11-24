// Requests for the evaluation: 35 attacks (all of which succeed with PROTECTION=none)
// adapted from the MongoDB Injection Dataset, PayloadsAllTheThings and NoSQLMap, and
// 25 benign ones. Each carries its own oracle, because the sanitizer baselines rewrite
// a query silently (200, no 403) so a status code is not enough. The oracles use the
// seed data: product names are unique, nothing costs <= 0, and no product is in
// category "zzz", which is also not a username.
// Query keys travel on the wire ("q[$regex]"); Express 4's extended parser nests them.
const loggedIn = (s, b) => s === 200 && b.success === true;
const extraRows = (s, b) => s === 200 && b.count > 1;
const anyRow = (s, b) => s === 200 && b.count > 0;
const oneRow = (s, b) => s === 200 && b.count === 1;
const noRow = (s, b) => s === 200 && b.count === 0;
const notFound = (s) => s === 404;
const leaked = (s, b) => s === 200 && typeof b.username === 'string';
const isUser = (name) => (s, b) => s === 200 && b.username === name;

// family: operator = injected query operator, js = JavaScript injected into $where,
// js-evasion = the same, without the tokens a signature filter looks for
const ATTACKS = [
  { name: 'login-ne-null', family: 'operator', path: '/login', json: { username: 'admin', password: { $ne: null } }, succeeded: loggedIn },
  { name: 'login-ne-empty', family: 'operator', path: '/login', json: { username: 'admin', password: { $ne: '' } }, succeeded: loggedIn },
  { name: 'login-gt-empty', family: 'operator', path: '/login', json: { username: 'admin', password: { $gt: '' } }, succeeded: loggedIn },
  { name: 'login-gte-empty', family: 'operator', path: '/login', json: { username: 'admin', password: { $gte: '' } }, succeeded: loggedIn },
  { name: 'login-nin', family: 'operator', path: '/login', json: { username: 'admin', password: { $nin: ['wrong'] } }, succeeded: loggedIn },
  { name: 'login-not-eq', family: 'operator', path: '/login', json: { username: 'admin', password: { $not: { $eq: 'wrong' } } }, succeeded: loggedIn },
  { name: 'login-exists', family: 'operator', path: '/login', json: { username: 'admin', password: { $exists: true } }, succeeded: loggedIn },
  { name: 'login-regex-any', family: 'operator', path: '/login', json: { username: 'admin', password: { $regex: '.*' } }, succeeded: loggedIn },
  { name: 'login-regex-user', family: 'operator', path: '/login', json: { username: { $regex: '^adm' }, password: { $ne: null } }, succeeded: loggedIn },
  { name: 'login-in-users', family: 'operator', path: '/login', json: { username: { $in: ['admin', 'root'] }, password: { $ne: null } }, succeeded: loggedIn },
  { name: 'login-any-user', family: 'operator', path: '/login', json: { username: { $ne: null }, password: { $ne: null } }, succeeded: loggedIn },
  // the same bypass through a urlencoded form body instead of JSON
  { name: 'login-form-ne', family: 'operator', path: '/login', form: { username: 'admin', 'password[$ne]': 'wrong' }, succeeded: loggedIn },
  { name: 'login-form-regex', family: 'operator', path: '/login', form: { 'username[$regex]': '^adm', 'password[$gt]': '' }, succeeded: loggedIn },

  { name: 'search-regex-any', family: 'operator', path: '/search', query: { 'q[$regex]': '.*' }, succeeded: extraRows },
  { name: 'search-regex-prefix', family: 'operator', path: '/search', query: { 'q[$regex]': '^L' }, succeeded: extraRows },
  { name: 'search-ne', family: 'operator', path: '/search', query: { 'q[$ne]': 'zzz' }, succeeded: extraRows },
  { name: 'search-gt-empty', family: 'operator', path: '/search', query: { 'q[$gt]': '' }, succeeded: extraRows },
  { name: 'search-nin', family: 'operator', path: '/search', query: { 'q[$nin][0]': 'zzz' }, succeeded: extraRows },
  { name: 'search-not-eq', family: 'operator', path: '/search', query: { 'q[$not][$eq]': 'zzz' }, succeeded: extraRows },
  { name: 'search-exists', family: 'operator', path: '/search', query: { 'q[$exists]': 'true' }, succeeded: extraRows },
  { name: 'search-in-list', family: 'operator', path: '/search', query: { 'q[$in][0]': 'Laptop', 'q[$in][1]': 'Novel' }, succeeded: extraRows },

  // /profile leaks another user's document, password and secret included
  { name: 'profile-ne', family: 'operator', path: '/profile', query: { 'username[$ne]': 'zzz' }, succeeded: leaked },
  { name: 'profile-regex-admin', family: 'operator', path: '/profile', query: { 'username[$regex]': '^adm' }, succeeded: leaked },
  { name: 'profile-gt-empty', family: 'operator', path: '/profile', query: { 'username[$gt]': '' }, succeeded: leaked },
  { name: 'profile-nin', family: 'operator', path: '/profile', query: { 'username[$nin][0]': 'zzz' }, succeeded: leaked },
  { name: 'profile-exists', family: 'operator', path: '/profile', query: { 'username[$exists]': 'true' }, succeeded: leaked },

  { name: 'filter-or-true', family: 'js', path: '/filter', query: { category: "zzz' || true || 'a", maxPrice: '0' }, succeeded: anyRow },
  { name: 'filter-tautology', family: 'js', path: '/filter', query: { category: "zzz' || '1'=='1' || 'a", maxPrice: '0' }, succeeded: anyRow },
  { name: 'filter-numeric-or-true', family: 'js', path: '/filter', query: { category: 'zzz', maxPrice: '0 || true' }, succeeded: anyRow },
  { name: 'filter-return-true', family: 'js', path: '/filter', query: { category: "zzz'; return true; var a = '", maxPrice: '0' }, succeeded: anyRow },
  { name: 'filter-this-price', family: 'js', path: '/filter', query: { category: "zzz' || this.price > 0 || 'a", maxPrice: '0' }, succeeded: anyRow },
  { name: 'filter-regex-match', family: 'js', path: '/filter', query: { category: "zzz' || this.name.match(/^L/) || 'a", maxPrice: '0' }, succeeded: anyRow },
  { name: 'filter-function', family: 'js', path: '/filter', query: { category: "zzz' || (function(){ return true })() || 'a", maxPrice: '0' }, succeeded: anyRow },
  // disguised as a ternary: no $ operator, no ||/&&, no quote break, no comment
  { name: 'filter-ternary', family: 'js-evasion', path: '/filter', query: { category: "zzz' ? 1 : '1", maxPrice: '99999' }, succeeded: anyRow },
  { name: 'filter-ternary-price', family: 'js-evasion', path: '/filter', query: { category: 'zzz', maxPrice: '0 ? 0 : 99999' }, succeeded: anyRow },
];

// Normal traffic: what MQM learns from and what false positives are measured on
// (a false positive is ok() failing). Ordered as a realistic mix, rarer variants
// last, because benign(f) takes a prefix. The last two leave out a parameter, so
// they have a query shape of their own and are the first to be falsely blocked.
const BENIGN = [
  { name: 'login-alice', path: '/login', json: { username: 'alice', password: 'alice123' }, ok: loggedIn },
  { name: 'search-laptop', path: '/search', query: { q: 'Laptop' }, ok: oneRow },
  { name: 'profile-alice', path: '/profile', query: { username: 'alice' }, ok: isUser('alice') },
  { name: 'filter-books', path: '/filter', query: { category: 'books', maxPrice: '500' }, ok: anyRow },

  { name: 'login-bob', path: '/login', json: { username: 'bob', password: 'bobpass' }, ok: loggedIn },
  { name: 'search-novel', path: '/search', query: { q: 'Novel' }, ok: oneRow },
  { name: 'profile-bob', path: '/profile', query: { username: 'bob' }, ok: isUser('bob') },
  { name: 'filter-electronics', path: '/filter', query: { category: 'electronics', maxPrice: '1000' }, ok: anyRow },

  { name: 'login-carol', path: '/login', json: { username: 'carol', password: 'carol!pw' }, ok: loggedIn },
  { name: 'search-kettle', path: '/search', query: { q: 'Kettle' }, ok: oneRow },
  { name: 'profile-carol', path: '/profile', query: { username: 'carol' }, ok: isUser('carol') },
  { name: 'filter-clothing', path: '/filter', query: { category: 'clothing', maxPrice: '800' }, ok: anyRow },

  { name: 'login-dave', path: '/login', json: { username: 'dave', password: 'dave2024' }, ok: loggedIn },
  { name: 'search-jacket', path: '/search', query: { q: 'Jacket' }, ok: oneRow },
  { name: 'profile-dave', path: '/profile', query: { username: 'dave' }, ok: isUser('dave') },
  { name: 'filter-home-no-max', path: '/filter', query: { category: 'home' }, ok: anyRow },

  { name: 'login-form-erin', path: '/login', form: { username: 'erin', password: 'erin-pass' }, ok: loggedIn },
  { name: 'search-no-hit', path: '/search', query: { q: 'Unicorn' }, ok: noRow },
  { name: 'profile-unknown', path: '/profile', query: { username: 'zoe' }, ok: notFound },
  { name: 'filter-unknown-category', path: '/filter', query: { category: 'garden', maxPrice: '500' }, ok: noRow },
  { name: 'login-wrong-password', path: '/login', json: { username: 'alice', password: 'nope' }, ok: (s, b) => s === 401 && b.success === false },
  // harmless text that looks like a payload
  { name: 'search-url', path: '/search', query: { q: 'https://shop.example/lamp' }, ok: noRow },
  { name: 'search-price-text', path: '/search', query: { q: '$100 Desk Lamp' }, ok: noRow },
  { name: 'search-empty', path: '/search', ok: noRow },
  { name: 'profile-empty', path: '/profile', ok: notFound },
];

// Prefix of the benign pool, for the training-coverage runs: a smaller fraction is
// always a subset of a larger one.
const benign = (fraction = 1) =>
  BENIGN.slice(0, Math.min(BENIGN.length, Math.max(1, Math.ceil(BENIGN.length * fraction))));

module.exports = { ATTACKS, BENIGN, benign };
