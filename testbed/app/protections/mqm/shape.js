// Shape extraction: reduce a MongoDB query to its structure, dropping values.
//
//   {username: "alice", password: "x"}        -> {password: "string", username: "string"}
//   {username: "admin", password: {$ne: null}} -> {password: {$ne: "null"}, username: "string"}
//   {$where: "this.a == 'b'"}                  -> {$where: "js:this . a == STR"}
//   {tags: {$in: ["a", "b", "c"]}}             -> {tags: {$in: ["string"]}}
//
// Shape grammar:
//   leaf   = type tag string ("string", "number", "null", "objectId", ...)
//          | "js:<token structure>" for server-side JavaScript
//   array  = sorted list of the distinct shapes of its elements (length is dropped)
//   object = object with the same keys (sorted), each mapped to the shape of its value
const { jsStructure } = require('./js-structure');

const MAX_DEPTH = 32;

// Keys whose string/function value is JavaScript executed by the server.
const JS_KEYS = new Set(['$where']);
const JS_KEYS_UNDER = new Map([ // Map, not object: keys are user-controlled ("toString")
  ['$function', new Set(['body'])],
  ['$accumulator', new Set(['init', 'accumulate', 'merge', 'finalize'])],
]);

const BSON_TYPES = {
  ObjectId: 'objectId', ObjectID: 'objectId',
  Int32: 'number', Double: 'number', Long: 'number', Decimal128: 'number',
  BSONRegExp: 'regex', Binary: 'binary', Timestamp: 'timestamp',
  Code: 'code', MinKey: 'minKey', MaxKey: 'maxKey', BSONSymbol: 'symbol', UUID: 'binary',
};

function leafType(v) {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string': return 'string';
    case 'number': case 'bigint': return 'number';
    case 'boolean': return 'boolean';
    case 'undefined': return 'undefined';
    case 'function': return 'function';
    case 'symbol': return 'symbol';
  }
  if (v instanceof Date) return 'date';
  if (v instanceof RegExp) return 'regex';
  if (Buffer.isBuffer(v) || ArrayBuffer.isView(v)) return 'binary';
  // Real BSON values are class instances. A plain object (from JSON or the query
  // string) claiming a _bsontype is user input posing as one: keep it a container.
  const proto = Object.getPrototypeOf(v);
  const plain = proto === Object.prototype || proto === null;
  if (!plain && typeof v._bsontype === 'string') return BSON_TYPES[v._bsontype] || v._bsontype;
  return null; // container (plain object or array)
}

function shapeOf(value, parentKey = null, key = null, depth = 0, seen = new WeakSet()) {
  const isJs = JS_KEYS.has(key) || (JS_KEYS_UNDER.has(parentKey) && JS_KEYS_UNDER.get(parentKey).has(key));
  if (isJs && (typeof value === 'string' || typeof value === 'function')) {
    return 'js:' + jsStructure(String(value));
  }
  if (isJs && value && value._bsontype === 'Code') {
    return 'js:' + jsStructure(String(value.code));
  }

  const leaf = leafType(value);
  if (leaf !== null) return leaf;
  if (depth >= MAX_DEPTH) return 'tooDeep';
  if (seen.has(value)) return 'cycle';
  seen.add(value);

  let out;
  if (Array.isArray(value)) {
    const distinct = new Map();
    for (const el of value) {
      const s = shapeOf(el, parentKey, null, depth + 1, seen);
      distinct.set(canonical(s), s);
    }
    out = [...distinct.keys()].sort().map((k) => distinct.get(k));
  } else {
    out = Object.create(null); // user-controlled keys such as "__proto__" stay plain keys
    for (const k of Object.keys(value).sort()) {
      out[k] = shapeOf(value[k], key, k, depth + 1, seen);
    }
  }
  seen.delete(value);
  return out;
}

// Deterministic string form, used as the identity of a shape.
function canonical(shape) {
  return JSON.stringify(shape);
}

module.exports = { shapeOf, canonical };
