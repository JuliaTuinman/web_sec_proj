// Baseline: Mongoose's own sanitizeFilter, applied to each filter at the driver
// level because the testbed has no ODM (mongoose is a dependency for this one
// function). It wraps operator objects in $eq, which neutralizes an attack silently
// (200, no 403), and throws on a top-level $where, which we report as a 403 - also
// for the legitimate /filter queries, this baseline's false positives.
const { sanitizeFilter } = require('mongoose');

// Filter-first methods. Aggregation pipelines are left alone, as in Mongoose.
const METHODS = ['find', 'findOne', 'countDocuments', 'deleteOne', 'deleteMany',
  'updateOne', 'updateMany', 'replaceOne', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace'];

function wrapCollection(coll) {
  for (const method of METHODS) {
    const orig = coll[method];
    if (typeof orig !== 'function') continue;
    coll[method] = function sanitized(filter, ...rest) {
      let clean;
      try {
        clean = sanitizeFilter(filter);
      } catch (e) {
        e.mqmBlocked = true; // the repo's "a defense rejected this query" flag -> 403
        e.message = `sanitizeFilter rejected query on ${coll.collectionName}: ${e.message}`;
        throw e;
      }
      return orig.call(this, clean, ...rest);
    };
  }
  return coll;
}

function wrapDb(db) {
  const collection = db.collection.bind(db);
  db.collection = (name, options) => wrapCollection(collection(name, options));
  return db;
}

module.exports = { wrapDb, wrapCollection };
