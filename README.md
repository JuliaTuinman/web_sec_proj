# MQM - MongoDB Query Monitor

MQM sits between a Node.js app and MongoDB and watches every query.
- **Learn mode:** records the normal "shape" of each query (fields, types, operators).
- **Enforce mode:** blocks and logs any query whose shape deviates (e.g. `password` becomes `{"$ne": null}`).

This repo contains the vulnerable **testbed** app, the defenses we compare (none, express-mongo-sanitize,
regex filter, MQM), and the evaluation harness.

> The testbed is **intentionally vulnerable**. Never deploy it or expose it beyond localhost.

## Status
| Piece | Owner | State |
|---|---|---|
| Testbed app, Docker, seed data | Julia | Done, smoke-tested |
| MQM (driver wrapping, shapes, modes) | Philip | Done, unit + end-to-end tested (`npm test`) |
| Payloads, baselines, traffic generator | Samson | Done: regex baseline, payload/baseline sets, traffic generator (`npm test`) |
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
| `PROTECTION=sanitizer docker compose up -d --force-recreate app` | switch defense |
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
  traffic/payloads.js     labeled benign + attack payload sets, with the oracles that judge a response
  traffic/generate.js     traffic generator: sends the payload sets, reports what each defense did
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
./testbed/learn-traffic.sh        # sends ONLY benign traffic to every endpoint
PROTECTION=mqm MQM_MODE=enforce docker compose up -d --force-recreate app
./testbed/smoke-test.sh
```
Skipping the learn step (or editing `routes.js`, since site keys include line numbers) leaves MQM with no matching
model, so **every** query, normal ones included, is blocked with "query site never seen in learn mode".
Delete `testbed/mqm-data/model.json` and relearn. If you add an endpoint, add benign requests for it to `learn-traffic.sh`
(and its benign + attack cases to `traffic/payloads.js`).
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

## Baselines and traffic generator

### Regex baseline (`PROTECTION=regex`)
Code: `testbed/app/protections/regex.js`. HTTP middleware on the same hook as the sanitizer. It scans every key and
string value in `req.body` and `req.query` (at any depth) and **blocks the whole request with 403**:

| Rule | Applies to | Matches |
|---|---|---|
| `OPERATOR_KEY` | keys | a key starting with `$` (`$ne`, `$gt`, `$regex`, ...) |
| `DOTTED_KEY` | keys | a key containing `.` |
| `JS_BREAKOUT` | values | a quote, `;`, `\|\|`, `&&`, `=>`, `//` or `/*` |
| `JS_KEYWORD` | values | the words `function`, `return`, `while`, `for`, `this`, `sleep` |
| `OPERATOR_VALUE` | values | a `$word` inside a string |

How it differs from the sanitizer: the sanitizer only strips `$`/`.` **keys** and lets the request run, so the
`/filter` `$where` injection (a plain string value) gets through it. The regex baseline also scans **values**, so it
catches that, and it rejects with 403 instead of neutralizing silently. Being a blocklist, it has known blind spots,
which the payload sets measure on purpose:
- **False positives:** benign input with a quote or keyword is blocked (a user named `o'brien`, a search for
  `Books for kids`).
- **Misses:** an injection that uses no listed characters gets through. `/filter` splices `maxPrice` in unquoted, so
  `maxPrice=0 ? 0 : 1` or `maxPrice=0, 1` turns the whole `$where` into a truthy constant. MQM catches both, because
  the JavaScript token structure changes.

| Env var | Values | Default |
|---|---|---|
| `REGEX_MODE` | `block` (403) / `monitor` (allow, log what would be blocked) | `block` |
| `REGEX_LOG` | JSONL file, one line per blocked/flagged request | set in compose |

A blocked request returns `{"error":"blocked","detail":"regex filter blocked request: operator key $ne at body.password"}`.

### Payload and baseline sets
`testbed/traffic/payloads.js` holds labeled benign and attack cases for all four endpoints, each in the parsed form
`req.body`/`req.query` takes. Each case carries an **oracle** that judges a response by content, not by status code
alone, so a silently neutralized attack still counts as stopped.

- `kind: 'benign'`: normal traffic. Cases marked `edge` are legitimate inputs a blocklist is likely to trip on.
- `kind: 'attack'`: injections. Cases marked `evasion` exploit the app while avoiding every regex signature.

### Traffic generator
Sends the payload sets to one running app and reports what the active defense did with each case:
`served` or `FALSE-POS` for benign cases, `stopped` or `EXPLOITED` for attacks.
```
cd testbed && npm run traffic                                    # human-readable report
cd testbed && npm run traffic -- http://localhost:3000 --json   # machine-readable, one entry per request
docker compose exec app npm run traffic                          # no Node on the host
```
Filters: `--only login,search` and `--kind benign|attack`. Run it against `PROTECTION=none` first to check the
corpus: every attack should report `EXPLOITED` and every benign case `served`.
It tests one configuration per run. Switching protections and building the comparison table is the harness's job;
`--json` output is meant to feed it.

## Seed data
10 users (`admin`, `alice`, `bob`, ... `ivan`) with plaintext passwords and a `secret` field, and 26 products across
4 categories (electronics, books, clothing, home). Plaintext passwords are deliberate: the login endpoint compares
them inside the query. Run `docker compose run --rm seed` to restore the original data.

## Integration points for teammates
- **Selecting a defense:** the `PROTECTION` env var (`none` | `sanitizer` | `regex` | `mqm`) loads
  `testbed/app/protections/<name>.js`. A protection module may export:
  - `middleware(req, res, next)`: HTTP-level filter (sanitizer, regex).
  - `wrapDb(db)` returning a db: driver-level wrapper (MQM). Called from `app/db.js`.
- **MQM:** create `protections/mqm.js` exporting `wrapDb(db)`. Wrap collection methods (`find`, `findOne`, ...).
  To block, throw an error with `err.mqmBlocked = true`; the routes turn it into a 403. Mode is
  `process.env.MQM_MODE` (`learn` | `enforce`).
- **Regex baseline:** `protections/regex.js` exports `middleware` (see "Baselines and traffic generator").
- **Sanitizer baseline:** `protections/sanitizer.js`, express-mongo-sanitize with its default config.
- **Harness:** switch setups by restarting `app` with a different `PROTECTION`; `GET /health` confirms it.
  Blocked requests return 403 (MQM, regex). The sanitizer neutralizes input silently, so judge an attack by the
  response content (e.g. login `success:false`), not by status code alone. The payload oracles already do this:
  run `npm run traffic -- --json` for each setup and aggregate the `outcome` fields.
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
