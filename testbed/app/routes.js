// The 4 intentionally vulnerable endpoints. Each passes user input straight into a query.
const express = require('express');
const { getDb } = require('./db');
const router = express.Router();

// Wrap async handlers; a blocked/failed query -> 403/500 JSON instead of a hang.
const h = (fn) => (req, res) =>
  fn(req, res).catch((err) => {
    const blocked = err && err.mqmBlocked;
    res.status(blocked ? 403 : 500).json({ error: blocked ? 'blocked' : 'server error', detail: err.message });
  });

// 1. LOGIN - auth bypass via operator injection.
//    Normal:  {"username":"alice","password":"alice123"}
//    Attack:  {"username":"admin","password":{"$ne":null}}
router.post('/login', h(async (req, res) => {
  const { username, password } = req.body;
  const user = await getDb().collection('users').findOne({ username, password });
  if (!user) return res.status(401).json({ success: false });
  res.json({ success: true, username: user.username, role: user.role });
}));

// 2. SEARCH - product search by name; operator/regex injection via query string.
//    Normal:  GET /search?q=laptop
//    Attack:  GET /search?q[$regex]=.*   or   /search?q[$ne]=x
router.get('/search', h(async (req, res) => {
  const { q } = req.query;
  const products = await getDb().collection('products').find({ name: q }).limit(50).toArray();
  res.json({ count: products.length, products });
}));

// 3. PROFILE - profile lookup by username; leaks other users' data (incl. secrets).
//    Normal:  GET /profile?username=alice
//    Attack:  GET /profile?username[$ne]=x   or   /profile?username[$regex]=^a
router.get('/profile', h(async (req, res) => {
  const { username } = req.query;
  const user = await getDb().collection('users').findOne({ username });
  if (!user) return res.status(404).json({ error: 'not found' });
  res.json(user); // returns the whole document, password and secret included (on purpose)
}));

// 4. FILTER - category filter built by string concatenation inside $where
//    (server-side JavaScript injection).
//    Normal:  GET /filter?category=electronics&maxPrice=500
//    Attack:  GET /filter?category=x'%7C%7Ctrue%7C%7C'a&maxPrice=0
router.get('/filter', h(async (req, res) => {
  const { category, maxPrice } = req.query;
  const products = await getDb().collection('products')
    .find({ $where: `this.category == '${category}' && this.price <= ${maxPrice || 1e9}` })
    .limit(50)
    .toArray();
  res.json({ count: products.length, products });
}));

module.exports = router;
