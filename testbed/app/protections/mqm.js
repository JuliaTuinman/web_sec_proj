// MQM - MongoDB Query Monitor. Loaded when PROTECTION=mqm (see protections/index.js).
// Wraps the driver handle in app/db.js; the implementation lives in ./mqm/.
//
// Environment:
//   MQM_MODE      learn | enforce | monitor            (default: learn)
//   MQM_MODEL     path of the learned model JSON       (default: ./mqm-data/model.json)
//   MQM_SITE_KEY  callsite | collection                (default: callsite)
//   MQM_UNKNOWN   block | allow  - queries from a site never seen while learning (default: block)
//   MQM_LOG       optional JSONL file that receives one line per blocked/flagged query
const { createGuard } = require('./mqm/guard');

let guard;

function wrapDb(db) {
  guard = createGuard({
    mode: process.env.MQM_MODE || 'learn',
    modelPath: process.env.MQM_MODEL || undefined,
    siteKeying: process.env.MQM_SITE_KEY || 'callsite',
    unknownSite: process.env.MQM_UNKNOWN || 'block',
    logPath: process.env.MQM_LOG || null,
  });
  return guard.wrapDb(db);
}

module.exports = { wrapDb, getGuard: () => guard };
