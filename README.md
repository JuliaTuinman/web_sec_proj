# MQM - MongoDB Query Monitor

MQM sits between a Node.js app and MongoDB and watches every query.
- **Learn mode:** records the normal "shape" of each query (fields, types, operators).
- **Enforce mode:** blocks and logs any query whose shape deviates (e.g. `password` becomes `{"$ne": null}`).

This repo contains the vulnerable **testbed** app, the defenses we compare (none, express-mongo-sanitize,
Mongoose `sanitizeFilter`, a regex filter, MQM), and the evaluation harness.

> The testbed is **intentionally vulnerable**. Never deploy it or expose it beyond localhost.

## Status
| Piece | Owner | State |
|---|---|---|
| Testbed app, Docker, seed data | Julia | Done, smoke-tested |
| MQM (driver wrapping, shapes, modes) | Philip | Done, unit + end-to-end tested (`npm test`) |
| Payloads, baselines, traffic generator | Samson | Done (`eval/`, `protections/regex.js`, `protections/sanitizefilter.js`) |
| Test harness, metrics, results table | teammate | TODO |

## Quick start
Prerequisite: Docker Desktop installed **and running**.

```
docker compose up --build -d
./testbed/smoke-test.sh
docker compose down
```
`up` starts mongo, seeds the DB and starts the app (PROTECTION=none). `smoke-test.sh` sends one normal and one attack
request per endpoint. `down` stops everything (add `-v` to also delete the DB volume).
App: http://localhost:3000, Mongo: localhost:27017. First run takes 1-3 minutes (image pulls).

Useful commands (copy one line at a time, without any trailing comment):

| Command | What it does |
|---|---|
| `docker compose logs -f app` | follow app logs |
| `docker compose ps -a` | container status (seed should show "Exited (0)") |
| `docker compose run --rm seed` | reset data to the original seed |
| `PROTECTION=sanitizer docker compose up -d --force-recreate --build app` | switch defense (`--build` picks up code changes) |
| `curl localhost:3000/health` | show which protection is active |

Without Docker: `cd testbed && npm i && MONGO_URL=mongodb://localhost:27017 npm run seed && npm start`.

## Layout
```
docker-compose.yml        mongo + seed job + vulnerable app
testbed/
  app/server.js           Express bootstrap (permissive body/query parsing on purpose)
  app/routes.js           4 vulnerable endpoints: /login /search /profile /filter
  app/db.js               ONE place the DB handle is created -> MQM wraps it here
  app/protections/        pluggable defenses chosen by PROTECTION env var
  eval/payloads.js        35 attack payloads + 25 benign requests, each with its own oracle
  eval/traffic.js         traffic generator: sends them, prints JSONL + a summary
  seed/seed.js            deterministic reseed (10 users, 26 products)
  smoke-test.sh           normal + attack request for each endpoint
```

## Endpoints and example attacks
| Endpoint | Normal request | Attack |
|---|---|---|
| `POST /login` | `{"username":"alice","password":"alice123"}` | `{"username":"admin","password":{"$ne":null}}` logs in as admin |
| `GET /search?q=` | `q=Laptop` (1 result) | `q[$regex]=.*` returns all 26 products |
| `GET /profile?username=` | `username=alice` | `username[$ne]=x` leaks admin's password and secret |
| `GET /filter?category=&maxPrice=` | `category=books&maxPrice=500` (5 results) | `category=x' \|\| true \|\| 'a&maxPrice=0` (`$where` JS injection) returns everything |

Normal query shapes (what MQM should learn): login = `{username: string, password: string}`;
search = `{name: string}`; profile = `{username: string}`; filter = `{$where: string}` with a text category and a number.

## MQM detector
Code: `testbed/app/protections/mqm.js` (entry, reads env) and `testbed/app/protections/mqm/`:

| File | Role |
|---|---|
| `guard.js` | wraps `db.collection()` so `find`, `findOne`, `updateOne`, `aggregate`, ... call `check()` first; learn/enforce/monitor logic |
| `shape.js` | query -> shape: keeps fields, operators, value types; drops values; arrays become the set of element shapes |
| `js-structure.js` | `$where` JavaScript -> token structure with literals replaced (`this . category == STR && this . price <= NUM`) |
| `callsite.js` | query-site key = `<collection>.<method>@<file>:<line>` of the app code that issued the query |
| `diff.js` | explains a block against the closest learned shape (`NEW_OPERATOR`, `TYPE_MISMATCH`, `JS_STRUCTURE`, ...) |
| `model.js` | learned model, saved as readable JSON |

Learn, then enforce:
```
PROTECTION=mqm MQM_MODE=learn docker compose up --build -d
node testbed/eval/traffic.js benign   # sends ONLY benign traffic (learn-traffic.sh calls this too)
PROTECTION=mqm MQM_MODE=enforce docker compose up -d --force-recreate app
./testbed/smoke-test.sh
```
Skipping the learn step (or editing `routes.js`, since site keys include line numbers) leaves MQM with no matching
model, so **every** query, normal ones included, is blocked with "query site never seen in learn mode".
Delete `testbed/mqm-data/model.json` and relearn. If you add an endpoint, add benign requests for it to `eval/payloads.js`.
The model is written to `testbed/mqm-data/model.json` (bind-mounted, gitignored), so it survives the restart.
New shapes are saved immediately; counts are flushed within 1 s. Learning adds to an existing model: delete the file
(or point `MQM_MODEL` elsewhere) to start fresh, e.g. for each training-coverage run.

| Env var | Values | Default |
|---|---|---|
| `MQM_MODE` | `learn` (record, never block) / `enforce` (block) / `monitor` (log only) | `learn` |
| `MQM_MODEL` | path of model JSON | `./mqm-data/model.json` |
| `MQM_SITE_KEY` | `callsite` / `collection` (coarser: one model per collection+method) | `callsite` |
| `MQM_UNKNOWN` | `block` / `allow` queries from a site never seen while learning | `block` |
| `MQM_LOG` | JSONL file, one line per blocked/flagged query (site, shape, reasons) | set in compose |

For the harness: a blocked query returns **403** with `detail` naming the site and reasons, e.g.
`MQM blocked query at users.findOne@app/routes.js:18: object where string expected at filter.password; new operator $ne at filter.password`.

Notes and limitations:
- Site keys contain line numbers: **relearn after editing `routes.js`**, or use `MQM_SITE_KEY=collection`.
- Shapes are exact: a benign request whose shape was never seen in training (e.g. a missing field, a number
  instead of a string) is blocked. That is the false-positive rate the coverage experiment measures.
- Attacks that keep the shape get through (e.g. a malicious pattern inside a `$regex` the site already uses).
- Not inspected: `insert*` documents, cursor modifiers such as `.sort(userInput)`, regex literals inside `$where`
  (lexed as division, so they can only cause false positives, never misses).
- Overhead (microbenchmark, M-series Mac): ~9 µs/query with `callsite` keying (mostly stack capture),
  ~1-3 µs with `collection` keying.

## Payloads, baselines and traffic
`testbed/eval/payloads.js` holds the requests, `testbed/eval/traffic.js` sends them.

35 attacks, adapted from the MongoDB Injection Dataset, PayloadsAllTheThings and NoSQLMap and reduced to the ones that
exploit this testbed: **all 35 succeed with `PROTECTION=none`**. Plus 25 benign requests over all 4 endpoints (valid
logins, a form login, a wrong password, searches that hit and miss, an unknown user, filters with and without
`maxPrice`), including text that only looks malicious (a pasted URL, `$100 Desk Lamp`) and two with a parameter left
out, which have a query shape of their own. Every request carries its own oracle - `succeeded(status, body)` for an
attack, `ok(status, body)` for a benign one - because the sanitizer baselines rewrite a query silently (200, no 403),
so a status code is not enough.

| Family | Count | What it is |
|---|---|---|
| `operator` | 26 | injected operators (`$ne`, `$gt`, `$regex`, `$in`, `$exists`, `$not`, ...) on `/login` (JSON and form body), `/search`, `/profile` |
| `js` | 7 | JavaScript injected into the `$where` string of `/filter` (tautology, `return`, a function expression, a regex literal) |
| `js-evasion` | 2 | the same, written as a ternary: none of the tokens a signature filter looks for |

```
node testbed/eval/traffic.js benign|attack|all [--base URL] [--fraction 0..1] [--repeat N]
```
JSONL on stdout (`{kind, name, family, path, status, ms, blocked, outcome}`; the first line records which protection
answered), summary on stderr. `--fraction` sends the first F of the benign pool (training-coverage runs; a smaller F
is always a subset of a larger one), `--repeat` sends everything N times (latency runs). `learn-traffic.sh` calls it
too, so learning and measuring always use the same traffic.

One pass over the 5 setups (MQM learned from the full benign pool first):

| Setup | Attacks prevented | operator | js | js-evasion | False positives |
|---|---|---|---|---|---|
| `none` | 0/35 | 0/26 | 0/7 | 0/2 | 0/25 |
| `sanitizer` (express-mongo-sanitize) | 26/35 | 26/26 | 0/7 | 0/2 | 0/25 |
| `sanitizefilter` (Mongoose) | 35/35 | 26/26 | 7/7 | 2/2 | 5/25 - every legitimate `$where` query |
| `regex` (signatures) | 33/35 | 26/26 | 7/7 | 0/2 | 1/25 - a URL pasted into the search box |
| `mqm` (enforce) | 35/35 | 26/26 | 7/7 | 2/2 | 0/25 |

MQM false positives vs training coverage (delete the model, learn with `--fraction F`, measure the full pool):
10% -> 7/25, 50% -> 2/25, 100% -> 0/25. Latency is the `ms` field of every line; the harness owner runs that
properly with `--repeat`.

- `protections/regex.js` - 5 WAF-style rules (mongo operator, server-side JS, tautology, quote break, JS comment)
  tested per key and value, not on the request as one JSON string: the quotes `JSON.stringify` adds match
  `quote-break` on their own and block everything.
- `protections/sanitizefilter.js` - Mongoose's `sanitizeFilter` applied to each filter at the driver level, since the
  testbed has no ODM. It wraps operators in `$eq` and **throws on a top-level `$where`**, so it stops JS injection
  but also rejects all 5 legitimate `/filter` requests (reported as 403).

Known gap: no endpoint accepts an operator the app itself uses (the proposal's search that legitimately uses
`$regex`), so the HTTP filters' false-positive rates are a lower bound and MQM's "precise, not blanket" claim only
shows in `npm test`. Needs one more endpoint in `routes.js`, benign requests for it, and a relearn.

## Seed data
10 users (`admin`, `alice`, `bob`, ... `ivan`) with plaintext passwords and a `secret` field, and 26 products across
4 categories (electronics, books, clothing, home). Plaintext passwords are deliberate: the login endpoint compares
them inside the query. Run `docker compose run --rm seed` to restore the original data.

## Integration points for teammates
- **Selecting a defense:** the `PROTECTION` env var (`none` | `sanitizer` | `sanitizefilter` | `regex` | `mqm`) loads
  `testbed/app/protections/<name>.js`. A protection module may export:
  - `middleware(req, res, next)`: HTTP-level filter (sanitizer, regex).
  - `wrapDb(db)` returning a db: driver-level wrapper (MQM, sanitizefilter). Called from `app/db.js`.
- **MQM:** create `protections/mqm.js` exporting `wrapDb(db)`. Wrap collection methods (`find`, `findOne`, ...).
  To block, throw an error with `err.mqmBlocked = true`; the routes turn it into a 403. Mode is
  `process.env.MQM_MODE` (`learn` | `enforce`).
- **Baselines:** `sanitizer.js` (express-mongo-sanitize), `regex.js` (signature matching), `sanitizefilter.js`
  (Mongoose `sanitizeFilter`) - see "Payloads, baselines and traffic".
- **Harness:** switch setups by restarting `app` with a different `PROTECTION`; `GET /health` confirms it.
  Blocked requests return 403 (MQM, regex, and sanitizefilter on `$where`). The sanitizer neutralizes input
  silently, so judge an attack by the response content (e.g. login `success:false`), not by status code alone -
  `eval/payloads.js` carries an oracle per request, and `eval/traffic.js` prints the JSONL the harness needs.
- **Resetting between runs:** `docker compose run --rm seed`.

## Troubleshooting
- **`docker: command not found`:** open Docker Desktop once, then open a new terminal. If still missing:
  `export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"`.
- **"Cannot connect to the Docker daemon":** Docker Desktop isn't running.
- **Port 3000 or 27017 already in use:** stop whatever uses it, or change the left side of the `ports` mapping in `docker-compose.yml`.
- **Code changes not showing up:** rebuild with `docker compose up --build -d`.
- **Endless "Connection accepted/ended" lines in the Mongo log:** just the healthcheck; use `docker compose logs app seed`.

## Git workflow
Work on a branch (`<name>/<topic>`) and open a PR into `main`.
