// Baseline: express-mongo-sanitize (strips keys starting with $ or containing .)
// Default config on purpose: it is the out-of-the-box usage this baseline represents.
// It only inspects keys, so string-value injection such as /filter's $where gets through.
const mongoSanitize = require('express-mongo-sanitize');
module.exports = { middleware: mongoSanitize() };
