// Baseline: signature matching. WAF-style rules over every key and value of the
// request, so an operator is caught as a key ("password[$ne]=x") or inside a $where
// value. Rules are tested per string, not on the whole request as JSON: the quotes
// JSON.stringify adds would match quote-break on their own. Blocks with 403 like MQM.
const RULES = [
  ['mongo-operator', /\$(?:ne|eq|gt|gte|lt|lte|in|nin|not|nor|or|and|all|size|mod|exists|type|regex|options|where|expr|text|elemMatch|function|accumulator|jsonSchema)\b/i],
  ['server-side-js', /this\s*\.|function\s*\(|=>|return\s+(?:true|false|this|\d|')|\b(?:sleep|while)\s*\(/i],
  ['tautology', /(?:\|\||&&)\s*(?:!?true|!?\d|'[^']*'\s*==)/i],
  ['quote-break', /['"]\s*(?:;|\)|\}|\]|\|\||&&|\/\/|\/\*)/],
  ['js-comment', /\/\/|\/\*/],
];

function* strings(value, depth = 0) {
  if (value == null || depth > 8) return;
  if (typeof value !== 'object') return yield String(value);
  for (const [key, inner] of Object.entries(value)) {
    yield key;
    yield* strings(inner, depth + 1);
  }
}

// Name of the first rule the request trips, or null.
function match(req) {
  for (const text of strings({ query: req.query, body: req.body })) {
    for (const [rule, pattern] of RULES) if (pattern.test(text)) return rule;
  }
  return null;
}

function middleware(req, res, next) {
  const rule = match(req);
  if (rule) return res.status(403).json({ error: 'blocked', detail: `regex filter: ${rule}` });
  next();
}

module.exports = { middleware, match, RULES };
