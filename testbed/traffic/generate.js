#!/usr/bin/env node
// Traffic generator: sends the benign + attack payload sets (traffic/payloads.js) to a
// running testbed and reports what happened under whichever PROTECTION is active.
//
//   node traffic/generate.js [baseUrl] [--only login,search] [--kind attack] [--json]
//   npm run traffic -- http://localhost:3000 --json
//
// Per case it prints one of:
//   served     benign request answered normally          (correct)
//   FALSE-POS  benign request blocked or broken           (defense over-reached)
//   stopped    attack blocked or neutralized              (correct)
//   EXPLOITED  attack achieved its goal                   (defense missed it)
// then a per-endpoint and overall tally. With --json it prints one JSON object with a
// `results` array (one entry per request) and a `summary` - the shape the metrics /
// results-table harness (the other TODO) is meant to consume. It intentionally does
// NOT switch protections or build a cross-defense comparison table; point it at one
// running config at a time.
const { endpoints, allCases } = require('./payloads');

const enc = (x) => encodeURIComponent(String(x));

// Serialize a query object into the bracket notation qs (the app's 'extended' parser)
// reads back: {q: {$regex: '.*'}} -> ?q[$regex]=.*  ; {q: ['a','b']} -> ?q=a&q=b
function encodeQuery(obj) {
  if (!obj) return '';
  const parts = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined) continue;
    if (Array.isArray(v)) v.forEach((el) => parts.push(`${k}=${enc(el)}`));
    else if (v && typeof v === 'object') for (const [sk, sv] of Object.entries(v)) parts.push(`${k}[${sk}]=${enc(sv)}`);
    else parts.push(`${k}=${enc(v)}`);
  }
  return parts.length ? '?' + parts.join('&') : '';
}

async function send(base, c) {
  const url = base + c.path + (c.method === 'GET' ? encodeQuery(c.query) : '');
  const init = { method: c.method };
  if (c.body !== undefined) {
    init.headers = { 'content-type': 'application/json' };
    init.body = JSON.stringify(c.body);
  }
  const resp = await fetch(url, init);
  let body = null;
  try { body = await resp.json(); } catch { /* non-JSON body */ }
  return { status: resp.status, body };
}

function classify(c, res) {
  const success = !!c.ok(res); // benign: served normally; attack: exploited
  if (c.kind === 'benign') return success ? 'served' : 'FALSE-POS';
  return success ? 'EXPLOITED' : 'stopped';
}

function parseArgs(argv) {
  const opts = { base: process.env.BASE_URL || 'http://localhost:3000', only: null, kind: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--only') opts.only = new Set(argv[++i].split(','));
    else if (a === '--kind') opts.kind = argv[++i];
    else if (!a.startsWith('--')) opts.base = a;
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  let cases = allCases();
  if (opts.only) cases = cases.filter((c) => opts.only.has(c.endpoint));
  if (opts.kind) cases = cases.filter((c) => c.kind === opts.kind);

  let health = null;
  try { health = (await send(opts.base, { method: 'GET', path: '/health' })).body; }
  catch (e) {
    console.error(`cannot reach ${opts.base} - is the app running? (${e.message})`);
    process.exit(1);
  }

  const results = [];
  for (const c of cases) {
    let res, outcome, error = null;
    try { res = await send(opts.base, c); outcome = classify(c, res); }
    catch (e) { res = { status: 0, body: null }; outcome = c.kind === 'benign' ? 'FALSE-POS' : 'stopped'; error = e.message; }
    results.push({
      endpoint: c.endpoint, name: c.name, kind: c.kind, edge: c.edge, evasion: c.evasion,
      status: res.status, outcome, error,
    });
  }

  const summary = summarize(results);
  if (opts.json) {
    console.log(JSON.stringify({ base: opts.base, protection: health && health.protection, health, summary, results }, null, 2));
    return;
  }
  printReport(opts, health, results, summary);
}

function summarize(results) {
  const s = { benign: { total: 0, served: 0, falsePos: 0 }, attack: { total: 0, stopped: 0, exploited: 0 } };
  for (const r of results) {
    if (r.kind === 'benign') { s.benign.total++; if (r.outcome === 'served') s.benign.served++; else s.benign.falsePos++; }
    else { s.attack.total++; if (r.outcome === 'stopped') s.attack.stopped++; else s.attack.exploited++; }
  }
  return s;
}

function printReport(opts, health, results, s) {
  console.log(`traffic -> ${opts.base}  (PROTECTION=${(health && health.protection) || '?'}` +
    `${health && health.mqmMode ? `, MQM_MODE=${health.mqmMode}` : ''})\n`);
  const label = { served: 'served   ', 'FALSE-POS': 'FALSE-POS', stopped: 'stopped  ', EXPLOITED: 'EXPLOITED' };
  for (const ep of Object.keys(endpoints)) {
    const rows = results.filter((r) => r.endpoint === ep);
    if (!rows.length) continue;
    console.log(`  ${ep}`);
    for (const r of rows) {
      console.log(`    ${label[r.outcome]}  ${r.kind.padEnd(6)}  ${r.name}` +
        `${r.status ? `  (${r.status})` : ''}${r.error ? `  ${r.error}` : ''}`);
    }
  }
  console.log(`\n  benign served ${s.benign.served}/${s.benign.total} (${s.benign.falsePos} false positive)` +
    `   attacks stopped ${s.attack.stopped}/${s.attack.total} (${s.attack.exploited} exploited)`);
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });

module.exports = { encodeQuery, classify, summarize };
