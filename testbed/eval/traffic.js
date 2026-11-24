#!/usr/bin/env node
// Sends eval/payloads.js at a running testbed: one JSON line per request on stdout
// {kind, name, family, path, status, ms, blocked, outcome}, summary on stderr.
// outcome: succeeded|prevented for attacks, served|rejected (= false positive) for benign.
//
//   node eval/traffic.js benign|attack|all [--base URL] [--fraction 0..1] [--repeat N]
//
// --fraction sends only the first F of the benign pool (training-coverage runs),
// --repeat sends everything N times (latency runs).
const { ATTACKS, benign } = require('./payloads');

const argv = process.argv.slice(2);
const what = argv[0] && !argv[0].startsWith('--') ? argv[0] : 'all';
const opt = (name, fallback) => (argv.indexOf(`--${name}`) === -1 ? fallback : argv[argv.indexOf(`--${name}`) + 1]);
const BASE = opt('base', process.env.BASE || 'http://localhost:3000');
const fraction = Number(opt('fraction', 1));
const repeat = Number(opt('repeat', 1));

if (!['benign', 'attack', 'all'].includes(what) || !(fraction > 0 && fraction <= 1) || !(repeat >= 1)) {
  console.error('usage: node eval/traffic.js [benign|attack|all] [--base URL] [--fraction 0..1] [--repeat N]');
  process.exit(2);
}

async function send(r) {
  const url = new URL(r.path, BASE);
  for (const [k, v] of Object.entries(r.query || {})) url.searchParams.append(k, v);
  const init = { method: r.json || r.form ? 'POST' : 'GET' };
  if (r.json) init.headers = { 'content-type': 'application/json' };
  if (r.json) init.body = JSON.stringify(r.json);
  if (r.form) init.headers = { 'content-type': 'application/x-www-form-urlencoded' };
  if (r.form) init.body = new URLSearchParams(r.form).toString();
  const started = process.hrtime.bigint();
  const res = await fetch(url, init);
  const text = await res.text();
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  let body;
  try { body = JSON.parse(text); } catch { body = { raw: text.slice(0, 200) }; }
  return { status: res.status, body, ms };
}

const rows = [];

async function run(kind, requests) {
  for (const r of requests) {
    let row;
    try {
      const { status, body, ms } = await send(r);
      const good = kind === 'attack' ? r.succeeded(status, body) : r.ok(status, body);
      row = { kind, name: r.name, family: r.family || null, path: r.path, status, ms: Number(ms.toFixed(3)),
        blocked: status === 403,
        outcome: kind === 'attack' ? (good ? 'succeeded' : 'prevented') : (good ? 'served' : 'rejected') };
    } catch (e) {
      row = { kind, name: r.name, path: r.path, status: 0, outcome: 'error', error: e.message };
    }
    rows.push(row);
    console.log(JSON.stringify(row));
  }
}

const pick = (kind, outcome) => rows.filter((r) => r.kind === kind && r.outcome === outcome);
const pct = (part, total) => (total ? `${((100 * part) / total).toFixed(1)}%` : 'n/a');
const quantile = (xs, q) => (xs.length ? [...xs].sort((a, b) => a - b)[Math.floor(q * (xs.length - 1))] : 0);
const listed = (rs) => rs.map((r) => `${r.name}(${r.status})`).join(', ');

async function main() {
  let health;
  try {
    health = await (await fetch(new URL('/health', BASE))).json();
  } catch (e) {
    console.error(`cannot reach ${BASE}: ${e.message}`);
    process.exit(1);
  }
  console.log(JSON.stringify({ kind: 'run', base: BASE, ...health, fraction, repeat, ts: new Date().toISOString() }));
  if (what !== 'benign' && health.protection === 'mqm' && health.mqmMode === 'learn') {
    console.error('WARNING: MQM is in learn mode - it will learn the attack shapes as normal traffic');
  }

  for (let i = 0; i < repeat; i++) {
    if (what !== 'attack') await run('benign', benign(fraction));
    if (what !== 'benign') await run('attack', ATTACKS);
  }

  const attacks = rows.filter((r) => r.kind === 'attack');
  const benigns = rows.filter((r) => r.kind === 'benign');
  const out = [`protection=${health.protection}${health.protection === 'mqm' ? ` mqmMode=${health.mqmMode}` : ''} base=${BASE}`];
  if (attacks.length) {
    out.push(`attacks: ${attacks.length} sent, ${pick('attack', 'prevented').length} prevented (${pct(pick('attack', 'prevented').length, attacks.length)}), ${attacks.filter((r) => r.blocked).length} answered 403`);
    for (const family of ['operator', 'js', 'js-evasion']) {
      const fam = attacks.filter((r) => r.family === family);
      if (fam.length) out.push(`  ${family}: ${fam.filter((r) => r.outcome === 'prevented').length}/${fam.length} prevented`);
    }
    if (pick('attack', 'succeeded').length) out.push(`  succeeded: ${pick('attack', 'succeeded').map((r) => r.name).join(', ')}`);
  }
  if (benigns.length) {
    out.push(`benign: ${benigns.length} sent, ${pick('benign', 'rejected').length} rejected = false positives (${pct(pick('benign', 'rejected').length, benigns.length)})`);
    if (pick('benign', 'rejected').length) out.push(`  rejected: ${listed(pick('benign', 'rejected'))}`);
  }
  const ms = rows.filter((r) => typeof r.ms === 'number').map((r) => r.ms);
  out.push(`latency: median ${quantile(ms, 0.5).toFixed(2)} ms, p95 ${quantile(ms, 0.95).toFixed(2)} ms over ${ms.length} requests`);
  const errors = pick('attack', 'error').length + pick('benign', 'error').length;
  if (errors) out.push(`${errors} requests failed to send`);
  console.error(out.join('\n'));
  if (errors) process.exit(1);
}

main();
