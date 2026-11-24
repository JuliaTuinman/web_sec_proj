// Payload and baseline sets for the four testbed endpoints, plus the oracles that
// judge an HTTP response. One source of truth, consumed two ways:
//   - traffic/generate.js serializes each case to a real HTTP request and classifies
//     the response (benign served? attack stopped?).
//   - the tests feed each case straight into a protection to assert what it does.
//
// Each case:
//   name     short label
//   kind     'benign' (baseline / normal traffic) or 'attack' (injection)
//   body     JSON body (POST) - already in parsed form, as req.body would be
//   query    query object - already in the nested form qs produces, as req.query would be
//            (e.g. {q: {$regex: '.*'}} is what ?q[$regex]=.* parses to)
//   ok       benign only, optional: overrides the endpoint's benignOk for this case
//   edge     benign only: a legitimate input that a blocklist is likely to trip on
//            (a quote, a keyword). These are what measure a defense's false positives.
//   exploited attack only: true when the response shows the attack achieved its goal
//            against an UNPROTECTED app; a defense "stops" the attack when this is false
//   evasion  attack only: crafted to avoid every signature a regex blocklist looks for
//            while still exploiting the app. These are what measure a blocklist's misses.
//
// Oracles read a normalized response { status, body } where body is the parsed JSON
// (or null). They judge by content, not status alone: the sanitizer neutralizes input
// silently (HTTP 200 with an empty / failed result), so an attack is "stopped" whenever
// it did not achieve its goal, however the defense achieved that.

const endpoints = {
  // 1. LOGIN - operator injection bypasses the password check.
  login: {
    method: 'POST',
    path: '/login',
    benignOk: (res) => res.status === 200 && res.body && res.body.success === true,
    cases: [
      { name: 'alice/alice123', kind: 'benign', body: { username: 'alice', password: 'alice123' } },
      { name: 'bob/bobpass', kind: 'benign', body: { username: 'bob', password: 'bobpass' } },
      // carol's real password has a '!', a value the regex baseline must NOT flag.
      { name: 'carol/carol!pw', kind: 'benign', body: { username: 'carol', password: 'carol!pw' } },
      // Wrong-credential login with an apostrophe name: the app correctly answers 401.
      {
        name: "o'brien/pa;ss (edge)", kind: 'benign', edge: true,
        body: { username: "o'brien", password: 'pa;ss' },
        ok: (res) => res.status === 401 && res.body && res.body.success === false,
      },

      {
        name: 'password $ne null', kind: 'attack',
        body: { username: 'admin', password: { $ne: null } },
        exploited: (res) => res.status === 200 && res.body && res.body.success === true && res.body.role === 'admin',
      },
      {
        name: 'password $gt empty', kind: 'attack',
        body: { username: 'admin', password: { $gt: '' } },
        exploited: (res) => res.status === 200 && res.body && res.body.success === true && res.body.role === 'admin',
      },
      {
        name: 'username+password $ne null', kind: 'attack',
        body: { username: { $ne: null }, password: { $ne: null } },
        exploited: (res) => res.status === 200 && res.body && res.body.success === true,
      },
    ],
  },

  // 2. SEARCH - operator/regex injection turns an exact match into a full dump.
  search: {
    method: 'GET',
    path: '/search',
    // A benign search matches at most one product (names are unique); a leak returns many.
    benignOk: (res) => res.status === 200 && res.body && res.body.count <= 1,
    cases: [
      { name: 'q=Laptop', kind: 'benign', query: { q: 'Laptop' } },
      { name: 'q=Mouse', kind: 'benign', query: { q: 'Mouse' } },
      { name: 'q=Novel', kind: 'benign', query: { q: 'Novel' } },
      { name: "q=Kids' Books (edge)", kind: 'benign', edge: true, query: { q: "Kids' Books" } },
      { name: 'q=Books for kids (edge)', kind: 'benign', edge: true, query: { q: 'Books for kids' } },

      {
        name: 'q[$regex]=.*', kind: 'attack', query: { q: { $regex: '.*' } },
        exploited: (res) => res.status === 200 && res.body && res.body.count > 1,
      },
      {
        name: 'q[$ne]=x', kind: 'attack', query: { q: { $ne: 'x' } },
        exploited: (res) => res.status === 200 && res.body && res.body.count > 1,
      },
      {
        name: 'q[$gt]=(empty)', kind: 'attack', query: { q: { $gt: '' } },
        exploited: (res) => res.status === 200 && res.body && res.body.count > 1,
      },
    ],
  },

  // 3. PROFILE - operator injection leaks another user's full document (incl. secret).
  profile: {
    method: 'GET',
    path: '/profile',
    // Benign lookups return the requested (non-admin) user; an injection returns admin.
    benignOk: (res) => res.status === 200 && res.body && res.body.role === 'user',
    cases: [
      { name: 'username=alice', kind: 'benign', query: { username: 'alice' } },
      { name: 'username=bob', kind: 'benign', query: { username: 'bob' } },
      { name: 'username=carol', kind: 'benign', query: { username: 'carol' } },
      // Unknown apostrophe name: the app correctly answers 404.
      {
        name: "username=o'brien (edge)", kind: 'benign', edge: true, query: { username: "o'brien" },
        ok: (res) => res.status === 404,
      },

      {
        name: 'username[$ne]=x', kind: 'attack', query: { username: { $ne: 'x' } },
        exploited: (res) => res.status === 200 && res.body && res.body.username === 'admin',
      },
      {
        name: 'username[$regex]=^a', kind: 'attack', query: { username: { $regex: '^a' } },
        exploited: (res) => res.status === 200 && res.body && res.body.username === 'admin',
      },
      {
        name: 'username[$gt]=(empty)', kind: 'attack', query: { username: { $gt: '' } },
        exploited: (res) => res.status === 200 && res.body && res.body.username === 'admin',
      },
    ],
  },

  // 4. FILTER - $where is built by string concatenation: server-side JS injection.
  filter: {
    method: 'GET',
    path: '/filter',
    // A real category filter returns at most one category (never all 26 products).
    benignOk: (res) => res.status === 200 && res.body && res.body.count < 26,
    cases: [
      { name: 'books <=500', kind: 'benign', query: { category: 'books', maxPrice: '500' } },
      { name: 'electronics <=500', kind: 'benign', query: { category: 'electronics', maxPrice: '500' } },
      { name: 'home <=800', kind: 'benign', query: { category: 'home', maxPrice: '800' } },
      { name: 'clothing <=599.50 (decimal)', kind: 'benign', query: { category: 'clothing', maxPrice: '599.50' } },
      { name: 'books, no maxPrice', kind: 'benign', query: { category: 'books' } },

      {
        name: "category=x' || true || 'a", kind: 'attack',
        query: { category: "x' || true || 'a", maxPrice: '0' },
        exploited: (res) => res.status === 200 && res.body && res.body.count === 26,
      },
      {
        name: 'maxPrice=0 || true', kind: 'attack',
        query: { category: 'books', maxPrice: '0 || true' },
        exploited: (res) => res.status === 200 && res.body && res.body.count === 26,
      },
      {
        name: "category=' || this.price>0 || '", kind: 'attack',
        query: { category: "' || this.price > 0 || '", maxPrice: '1' },
        exploited: (res) => res.status === 200 && res.body && res.body.count === 26,
      },
      // maxPrice is spliced in unquoted, so no quote is needed to inject. A ternary or a
      // comma operator rewrites the whole expression to a truthy constant using only
      // characters no blocklist signature matches.
      {
        name: 'maxPrice=0 ? 0 : 1 (evasion)', kind: 'attack', evasion: true,
        query: { category: 'books', maxPrice: '0 ? 0 : 1' },
        exploited: (res) => res.status === 200 && res.body && res.body.count === 26,
      },
      {
        name: 'maxPrice=0, 1 (evasion)', kind: 'attack', evasion: true,
        query: { category: 'books', maxPrice: '0, 1' },
        exploited: (res) => res.status === 200 && res.body && res.body.count === 26,
      },
    ],
  },
};

// Flat list of { endpoint, method, path, name, kind, edge, evasion, body, query, ok }
// where ok(res) is the per-case success oracle (served for benign, exploited for attacks).
function allCases() {
  const out = [];
  for (const [endpoint, ep] of Object.entries(endpoints)) {
    for (const c of ep.cases) {
      out.push({
        endpoint, method: ep.method, path: ep.path,
        name: c.name, kind: c.kind, edge: !!c.edge, evasion: !!c.evasion, body: c.body, query: c.query,
        ok: c.kind === 'benign' ? (c.ok || ep.benignOk) : c.exploited,
      });
    }
  }
  return out;
}

module.exports = { endpoints, allCases };
