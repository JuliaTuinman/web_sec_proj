// The learned model: for each query site, the set of shapes seen in learn mode.
// Stored as human-readable JSON so it can be inspected and diffed.
//
// {
//   "version": 1,
//   "sites": {
//     "users.findOne@app/routes.js:20": {
//       "shapes": [ { "shape": {...}, "count": 42, "firstSeen": "2026-..." } ]
//     }
//   }
// }
const fs = require('fs');
const path = require('path');
const { canonical } = require('./shape');

class Model {
  constructor() {
    this.sites = new Map(); // site -> Map(canonical -> {shape, count, firstSeen})
  }

  has(site, canon) {
    const s = this.sites.get(site);
    return !!s && s.has(canon);
  }

  hasSite(site) {
    return this.sites.has(site);
  }

  shapesFor(site) {
    const s = this.sites.get(site);
    return s ? [...s.values()].map((e) => e.shape) : [];
  }

  // Returns true when the shape is new for this site.
  learn(site, canon, shape) {
    let s = this.sites.get(site);
    if (!s) this.sites.set(site, (s = new Map()));
    const entry = s.get(canon);
    if (entry) { entry.count++; return false; }
    s.set(canon, { shape, count: 1, firstSeen: new Date().toISOString() });
    return true;
  }

  toJSON() {
    const sites = {};
    for (const site of [...this.sites.keys()].sort()) {
      sites[site] = { shapes: [...this.sites.get(site).values()] };
    }
    return { version: 1, sites };
  }

  static fromJSON(obj) {
    const m = new Model();
    if (!obj || obj.version !== 1 || !obj.sites) throw new Error('MQM: unrecognized model file format');
    for (const [site, { shapes }] of Object.entries(obj.sites)) {
      const s = new Map();
      for (const e of shapes) s.set(canonical(e.shape), { ...e });
      m.sites.set(site, s);
    }
    return m;
  }

  static load(file) {
    if (!fs.existsSync(file)) return null;
    return Model.fromJSON(JSON.parse(fs.readFileSync(file, 'utf8')));
  }

  // Atomic write (temp file + rename) so a crash never leaves a half-written model.
  save(file) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.toJSON(), null, 2) + '\n');
    fs.renameSync(tmp, file);
  }

  stats() {
    let shapes = 0;
    for (const s of this.sites.values()) shapes += s.size;
    return { sites: this.sites.size, shapes };
  }
}

module.exports = { Model };
