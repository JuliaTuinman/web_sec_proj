// Baseline: regex blocklist (PROTECTION=regex). HTTP middleware on the same hook as
// the sanitizer: it inspects req.body and req.query before any route runs.
//
// Two kinds of signature:
//   key    a key that is a Mongo operator ($ne, $gt, $where, ...) or a dotted path
//          (a.b). This is how operator injection reaches the query.
//   value  a string value that looks like a server-side JavaScript breakout
//          ($where injection: a quote, logical operator, terminator or comment) or a
//          Mongo operator smuggled in as text.
//
// Unlike the sanitizer, which strips $-keys and lets the request run, this baseline
// BLOCKS the whole request with 403 and names what tripped. Scanning values is what
// lets it stop the /filter $where string injection that the sanitizer misses.
// Being a blocklist it is deliberately blunt: benign input containing a quote or ||
// is a false positive, and an attack with no matching pattern is a miss. Measuring
// both against MQM is the point of this baseline.
//
// Environment:
//   REGEX_MODE  block (403, default) | monitor (allow, but log what would be blocked)
//   REGEX_LOG   optional JSONL file that receives one line per blocked/flagged request
const fs = require('fs');

const MAX_DEPTH = 32;

const KEY_RULES = [
  { code: 'OPERATOR_KEY', re: /^\$/, label: 'operator key' },
  { code: 'DOTTED_KEY', re: /\./, label: 'dotted key' },
];

const VALUE_RULES = [
  { code: 'JS_BREAKOUT', re: /['"`;]|\|\||&&|=>|\/\*|\/\//, label: 'JavaScript breakout characters' },
  { code: 'JS_KEYWORD', re: /\b(?:function|return|while|for|this|sleep)\b/i, label: 'JavaScript keyword' },
  { code: 'OPERATOR_VALUE', re: /\$\w+/, label: 'Mongo operator' },
];

const MODES = new Set(['block', 'monitor']);

// Own data properties only. A JSON body such as {"__proto__": {...}} creates an own
// "__proto__" key; reading it with obj[k] would return the prototype instead.
function ownEntries(obj) {
  const out = [];
  for (const k of Object.getOwnPropertyNames(obj)) {
    const d = Object.getOwnPropertyDescriptor(obj, k);
    if (d && 'value' in d) out.push([k, d.value]);
  }
  return out;
}

function scan(value, path, out, depth = 0, seen = new WeakSet()) {
  if (typeof value === 'string') {
    for (const r of VALUE_RULES) if (r.re.test(value)) out.push({ code: r.code, path, label: r.label });
    return out;
  }
  if (!value || typeof value !== 'object') return out;
  if (depth >= MAX_DEPTH) { out.push({ code: 'TOO_DEEP', path, label: 'nesting too deep' }); return out; }
  if (seen.has(value)) return out;
  seen.add(value);

  if (Array.isArray(value)) {
    value.forEach((el, i) => scan(el, `${path}[${i}]`, out, depth + 1, seen));
  } else {
    for (const [k, v] of ownEntries(value)) {
      for (const r of KEY_RULES) if (r.re.test(k)) out.push({ code: r.code, path, key: k, label: r.label });
      scan(v, `${path}.${k}`, out, depth + 1, seen);
    }
  }
  seen.delete(value);
  return out;
}

// Reasons why a request would be blocked; [] when it is clean.
function findInjections({ body, query } = {}) {
  const out = [];
  scan(body, 'body', out);
  scan(query, 'query', out);
  return out;
}

function formatReason(r) {
  return r.key !== undefined ? `${r.label} ${r.key} at ${r.path}` : `${r.label} at ${r.path}`;
}

function makeMiddleware(opts = {}) {
  const mode = (opts.mode || process.env.REGEX_MODE || 'block').toLowerCase();
  if (!MODES.has(mode)) throw new Error(`regex: unknown mode "${mode}" (block | monitor)`);
  const logPath = opts.logPath !== undefined ? opts.logPath : process.env.REGEX_LOG || null;
  const log = opts.logger || ((line) => console.warn(line));
  const stats = { checked: 0, blocked: 0, flagged: 0 };

  function report(req, action, reasons) {
    const line = JSON.stringify({
      regex: action, ts: new Date().toISOString(), mode,
      method: req.method, url: req.originalUrl || req.url, reasons: reasons.map(formatReason),
    });
    log(`[regex] ${line}`);
    if (logPath) {
      try { fs.appendFileSync(logPath, line + '\n'); } catch (e) { log(`[regex] cannot write log: ${e.message}`); }
    }
  }

  function regexFilter(req, res, next) {
    stats.checked++;
    const reasons = findInjections(req);
    if (!reasons.length) return next();
    if (mode === 'monitor') {
      stats.flagged++;
      report(req, 'flagged', reasons);
      return next();
    }
    stats.blocked++;
    report(req, 'blocked', reasons);
    return res.status(403).json({
      error: 'blocked',
      detail: `regex filter blocked request: ${reasons.map(formatReason).join('; ')}`,
    });
  }

  regexFilter.stats = stats;
  regexFilter.mode = mode;
  return regexFilter;
}

module.exports = { middleware: makeMiddleware(), makeMiddleware, findInjections, formatReason, KEY_RULES, VALUE_RULES };
