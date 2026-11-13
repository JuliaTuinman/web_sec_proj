// INTENTIONALLY VULNERABLE. Do not deploy. Used to evaluate NoSQL-injection defenses.
const express = require('express');
const { connect } = require('./db');
const protections = require('./protections');

const app = express();

// Both parsers are deliberately permissive:
//  - express.json() lets attackers send {"password": {"$ne": null}}
//  - extended urlencoded/query (qs) turns password[$ne]=x into {password: {$ne: 'x'}}
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('query parser', 'extended');

async function main() {
  await connect();

  const protection = protections.load();
  if (protection.middleware) app.use(protection.middleware);

  app.get('/health', (req, res) =>
    res.json({ ok: true, protection: protections.NAME, mqmMode: process.env.MQM_MODE || null })
  );

  app.use('/', require('./routes'));

  const port = process.env.PORT || 3000;
  app.listen(port, () =>
    console.log(`testbed listening on :${port} (PROTECTION=${protections.NAME})`)
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
