// MQM core: wraps a MongoDB driver Db so every query method goes through check().
//
// Modes:
//   learn    record the shape of every query at its site; never blocks
//   enforce  block any query whose shape was never learned for its site
//   monitor  like enforce, but only logs (shadow mode, for measuring before blocking)
//
// Site keying:
//   callsite    "<collection>.<method>@<file>:<line>" (default; one model per query in the code)
//   collection  "<collection>.<method>" (coarser: fewer false positives, more false negatives)
const fs = require('fs');
const path = require('path');
const { shapeOf, canonical } = require('./shape');
const { explain, formatReason } = require('./diff');
const { Model } = require('./model');
const { callerLocation } = require('./callsite');

// Collection methods that take user-influenced query documents, and which of
// their arguments make up the query's structure.
const METHODS = {
  find: (a) => ({ filter: a[0] }),
  findOne: (a) => ({ filter: a[0] }),
  countDocuments: (a) => ({ filter: a[0] }),
  count: (a) => ({ filter: a[0] }),
  distinct: (a) => ({ key: a[0], filter: a[1] }),
  deleteOne: (a) => ({ filter: a[0] }),
  deleteMany: (a) => ({ filter: a[0] }),
  updateOne: (a) => ({ filter: a[0], update: a[1] }),
  updateMany: (a) => ({ filter: a[0], update: a[1] }),
  replaceOne: (a) => ({ filter: a[0] }),
  findOneAndUpdate: (a) => ({ filter: a[0], update: a[1] }),
  findOneAndDelete: (a) => ({ filter: a[0] }),
  findOneAndReplace: (a) => ({ filter: a[0] }),
  aggregate: (a) => ({ pipeline: a[0] }),
};

const MODES = new Set(['learn', 'enforce', 'monitor']);

function createGuard(opts = {}) {
  const mode = (opts.mode || 'learn').toLowerCase();
  if (!MODES.has(mode)) throw new Error(`MQM: unknown mode "${mode}" (learn | enforce | monitor)`);
  const siteKeying = opts.siteKeying || 'callsite';
  if (!['callsite', 'collection'].includes(siteKeying)) {
    throw new Error(`MQM: unknown site keying "${siteKeying}" (callsite | collection)`);
  }
  const root = opts.root || process.cwd();
  const modelPath = opts.modelPath || path.join(root, 'mqm-data', 'model.json');
  const unknownSite = opts.unknownSite || 'block'; // block | allow (enforce/monitor only)
  const logPath = opts.logPath || null;
  const log = opts.logger || ((line) => console.warn(line));
  const persist = opts.persist !== false;

  const model = (persist && Model.load(modelPath)) || new Model();
  const stats = { checked: 0, allowed: 0, blocked: 0, flagged: 0, learned: 0 };
  let depth = 0; // reentrancy: the driver's findOne() calls this.find() internally
  let flushTimer = null;

  if (mode !== 'learn' && model.stats().sites === 0) {
    log(`[MQM] WARNING: ${mode} mode with an empty model (${modelPath}); every query will be flagged`);
  }

  function save() {
    if (!persist) return;
    if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
    model.save(modelPath);
  }

  function scheduleFlush() {
    if (!persist || flushTimer) return;
    flushTimer = setTimeout(save, 1000);
    flushTimer.unref();
  }

  if (persist && mode === 'learn') process.on('exit', save);

  function report(event) {
    const line = JSON.stringify({ mqm: event.action, ts: new Date().toISOString(), mode, ...event });
    log(`[MQM] ${line}`);
    if (logPath) {
      try { fs.appendFileSync(logPath, line + '\n'); } catch (e) { log(`[MQM] cannot write log: ${e.message}`); }
    }
  }

  // Core decision. Returns {allowed, site, reasons}; throws nothing.
  function check(site, query) {
    stats.checked++;
    const shape = shapeOf(query);
    const canon = canonical(shape);

    if (mode === 'learn') {
      if (model.learn(site, canon, shape)) {
        stats.learned++;
        save(); // new shapes are rare: write immediately so learning survives a restart
        log(`[MQM] learned shape #${model.sites.get(site).size} for ${site}: ${canon}`);
      } else {
        scheduleFlush(); // just a count update
      }
      stats.allowed++;
      return { allowed: true, site, reasons: [] };
    }

    if (model.has(site, canon)) { stats.allowed++; return { allowed: true, site, reasons: [] }; }
    if (!model.hasSite(site) && unknownSite === 'allow') { stats.allowed++; return { allowed: true, site, reasons: [] }; }

    const reasons = explain(model.shapesFor(site), shape);
    const block = mode === 'enforce';
    if (block) stats.blocked++; else { stats.flagged++; stats.allowed++; }
    report({ action: block ? 'blocked' : 'flagged', site, shape: canon, reasons: reasons.map(formatReason), detail: reasons });
    return { allowed: !block, site, reasons };
  }

  function siteKey(collName, method) {
    const base = `${collName}.${method}`;
    return siteKeying === 'callsite' ? `${base}@${callerLocation(root)}` : base;
  }

  function wrapCollection(coll) {
    for (const [method, extract] of Object.entries(METHODS)) {
      const orig = coll[method];
      if (typeof orig !== 'function') continue;
      Object.defineProperty(coll, method, {
        configurable: true,
        writable: true,
        value: function mqmWrapped(...args) {
          if (depth > 0) return orig.apply(this, args); // internal driver call, already checked
          depth++;
          try {
            const q = extract(args);
            if (q.filter === undefined) q.filter = {};
            const site = siteKey(coll.collectionName, method);
            const verdict = check(site, q);
            if (!verdict.allowed) {
              const err = new Error(`MQM blocked query at ${site}: ${verdict.reasons.map(formatReason).join('; ')}`);
              err.mqmBlocked = true;
              err.mqm = verdict;
              throw err;
            }
            return orig.apply(this, args);
          } finally {
            depth--;
          }
        },
      });
    }
    return coll;
  }

  function wrapDb(db) {
    const origCollection = db.collection.bind(db);
    db.collection = (name, options) => wrapCollection(origCollection(name, options));
    log(`[MQM] mode=${mode} siteKeying=${siteKeying} model=${modelPath} (${JSON.stringify(model.stats())})`);
    return db;
  }

  return { mode, siteKeying, modelPath, model, stats, check, wrapCollection, wrapDb, save };
}

module.exports = { createGuard, METHODS };
