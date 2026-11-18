// Finds the application source line that issued a query: the first stack frame
// outside MQM itself, Node internals and node_modules (so queries issued through
// an ODM such as Mongoose are still attributed to the app code that called it).
const path = require('path');
const { fileURLToPath } = require('url');

const MQM_DIR = __dirname + path.sep;
const NODE_MODULES = `${path.sep}node_modules${path.sep}`;

function callerLocation(root) {
  const origPrepare = Error.prepareStackTrace;
  const origLimit = Error.stackTraceLimit;
  let frames;
  try {
    Error.prepareStackTrace = (_, callSites) => callSites;
    Error.stackTraceLimit = 30;
    const holder = {};
    Error.captureStackTrace(holder, callerLocation);
    frames = holder.stack;
  } finally {
    Error.prepareStackTrace = origPrepare;
    Error.stackTraceLimit = origLimit;
  }

  for (const f of frames || []) {
    let file = f.getFileName();
    if (!file || file.startsWith('node:')) continue;
    if (file.startsWith('file://')) file = fileURLToPath(file);
    if (file.startsWith(MQM_DIR) || file.includes(NODE_MODULES)) continue;
    const rel = path.relative(root, file).split(path.sep).join('/');
    return `${rel}:${f.getLineNumber()}`;
  }
  return 'unknown';
}

module.exports = { callerLocation };
