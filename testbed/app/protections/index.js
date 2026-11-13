// Selects the protection under test via PROTECTION env var:
//   none | sanitizer | regex | mqm
// Each protection module may export:
//   middleware(req, res, next)  - HTTP-level filter (sanitizer, regex)
//   wrapDb(db) -> db            - driver-level wrapper (mqm)
// Teammates: drop regex.js / mqm.js in this folder; nothing else needs to change.
const NAME = (process.env.PROTECTION || 'none').toLowerCase();

function load() {
  if (NAME === 'none') return {};
  if (NAME === 'sanitizer') return require('./sanitizer');
  try {
    return require(`./${NAME}`);
  } catch (e) {
    if (e.code === 'MODULE_NOT_FOUND') {
      throw new Error(`PROTECTION=${NAME} but protections/${NAME}.js does not exist yet`);
    }
    throw e;
  }
}

module.exports = { load, NAME };
