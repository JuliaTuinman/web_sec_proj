// Baseline: express-mongo-sanitize (strips keys starting with $ or containing .)
// Placed here only so the testbed runs end-to-end; the baselines owner may change config.
const mongoSanitize = require('express-mongo-sanitize');
module.exports = { middleware: mongoSanitize() };
