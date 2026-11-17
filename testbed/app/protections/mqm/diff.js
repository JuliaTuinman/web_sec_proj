// Explains WHY a query shape was rejected, by diffing it against the closest
// shape learned for the same query site. Reason codes:
//   NEW_OPERATOR     a $-operator the site never used (e.g. $ne, $where, $regex)
//   TYPE_MISMATCH    e.g. an object where a string was expected
//   JS_STRUCTURE     the server-side JavaScript has a different token structure
//   NEW_FIELD        a non-operator field the site never used
//   MISSING_FIELD    a field the site always sent is absent
//   UNKNOWN_SITE     no shape was ever learned for this query site
const { canonical } = require('./shape');

function kind(shape) {
  if (Array.isArray(shape)) return 'array';
  if (shape && typeof shape === 'object') return 'object';
  if (typeof shape === 'string' && shape.startsWith('js:')) return 'js';
  return shape; // leaf type tag
}

function collectOperators(shape, path, out) {
  if (Array.isArray(shape)) {
    for (const el of shape) collectOperators(el, path, out);
  } else if (shape && typeof shape === 'object') {
    for (const k of Object.keys(shape)) {
      const p = path ? `${path}.${k}` : k;
      if (k.startsWith('$')) out.push({ code: 'NEW_OPERATOR', path: path || '(root)', operator: k });
      collectOperators(shape[k], p, out);
    }
  }
  return out;
}

function diff(expected, actual, path = '', out = []) {
  const ke = kind(expected);
  const ka = kind(actual);

  if (ke !== ka) {
    out.push({ code: 'TYPE_MISMATCH', path: path || '(root)', expected: ke, actual: ka });
    collectOperators(actual, path, out);
    return out;
  }
  if (ke === 'js') {
    if (expected !== actual) {
      out.push({ code: 'JS_STRUCTURE', path, expected: expected.slice(3), actual: actual.slice(3) });
    }
    return out;
  }
  if (ke === 'array') {
    const known = new Set(expected.map(canonical));
    for (const el of actual) {
      if (known.has(canonical(el))) continue;
      if (expected.length) diff(expected[0], el, `${path}[]`, out);
      else out.push({ code: 'TYPE_MISMATCH', path: `${path}[]`, expected: 'empty array', actual: kind(el) });
    }
    return out;
  }
  if (ke === 'object') {
    for (const k of Object.keys(actual)) {
      const p = path ? `${path}.${k}` : k;
      if (!Object.hasOwn(expected, k)) {
        if (k.startsWith('$')) out.push({ code: 'NEW_OPERATOR', path: path || '(root)', operator: k });
        else out.push({ code: 'NEW_FIELD', path: p });
        collectOperators(actual[k], p, out);
      } else {
        diff(expected[k], actual[k], p, out);
      }
    }
    for (const k of Object.keys(expected)) {
      if (!Object.hasOwn(actual, k)) out.push({ code: 'MISSING_FIELD', path: path ? `${path}.${k}` : k });
    }
  }
  return out;
}

// learnedShapes: array of shape trees. Returns the reasons against the closest one.
function explain(learnedShapes, actual) {
  if (!learnedShapes.length) return [{ code: 'UNKNOWN_SITE' }];
  let best = null;
  for (const s of learnedShapes) {
    const d = diff(s, actual);
    if (!best || d.length < best.length) best = d;
  }
  return best;
}

function formatReason(r) {
  switch (r.code) {
    case 'NEW_OPERATOR': return `new operator ${r.operator} at ${r.path}`;
    case 'TYPE_MISMATCH': return `${r.actual} where ${r.expected} expected at ${r.path}`;
    case 'JS_STRUCTURE': return `JavaScript structure changed at ${r.path}`;
    case 'NEW_FIELD': return `unexpected field ${r.path}`;
    case 'MISSING_FIELD': return `missing field ${r.path}`;
    case 'UNKNOWN_SITE': return 'query site never seen in learn mode';
    default: return r.code;
  }
}

module.exports = { diff, explain, formatReason };
