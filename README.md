# MQM - MongoDB Query Monitor (testbed)

## Layout
```
docker-compose.yml        mongo + seed job + vulnerable app
testbed/
  app/server.js           Express bootstrap (permissive body/query parsing on purpose)
  app/routes.js           4 vulnerable endpoints: /login /search /profile /filter
  app/db.js               ONE place the DB handle is created -> MQM wraps it here
  app/protections/        pluggable defenses chosen by PROTECTION env var
  seed/seed.js            deterministic reseed (10 users, 24 products)
  smoke-test.sh           normal + attack request for each endpoint
```

## Run
```
docker compose up --build                      # PROTECTION=none (unprotected)
PROTECTION=sanitizer docker compose up -d --force-recreate app
PROTECTION=mqm MQM_MODE=learn docker compose up -d --force-recreate app
./testbed/smoke-test.sh
docker compose run --rm seed                   # reset data between runs
```
Mongo is exposed on localhost:27017, app on localhost:3000.
Without Docker: `cd testbed && npm i && MONGO_URL=mongodb://localhost:27017 npm run seed && npm start`.

## Endpoints
| Endpoint | Normal shape | Vulnerability |
|---|---|---|
| POST /login `{username,password}` | text, text | operator injection (`{"$ne":null}`) auth bypass |
| GET /search?q= | q = text | `q[$regex]`, `q[$ne]` |
| GET /profile?username= | username = text | `username[$ne]` leaks other users + secrets |
| GET /filter?category=&maxPrice= | text, number | `$where` JS string injection |

## Integration points for teammates
- **MQM**: create `testbed/app/protections/mqm.js` exporting `wrapDb(db)` (wrap collection methods
  `find/findOne/...`, throw an error with `err.mqmBlocked = true` to block; routes turn it into a 403).
  Mode comes from `process.env.MQM_MODE` (`learn` | `enforce`).
- **Regex filter baseline**: `protections/regex.js` exporting `middleware(req,res,next)`.
- **Sanitizer baseline**: already in `protections/sanitizer.js`.
- **Harness**: `GET /health` reports active protection; switch setups by restarting `app` with a different `PROTECTION`.
  Blocked requests return HTTP 403 (MQM/regex) - sanitizer neutralizes silently, so judge attacks by response content
  (e.g. login `success:false`), not status code alone.
