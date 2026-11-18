// Reduces a server-side JavaScript snippet (the body of a $where clause) to its
// syntactic structure: identifiers, keywords and punctuation are kept, literal
// values are replaced by placeholders.
//
//   this.category == 'books' && this.price <= 500
//     -> "this . category == STR && this . price <= NUM"
//
// An injected quote changes the token sequence, so the same template filled with
// different *data* always gives the same structure, while input that escapes a
// string literal and adds *code* gives a different one (Su & Wassermann's
// definition of injection, applied to the JS inside a MongoDB query).
//
// This is a tokenizer, not a parser. It follows JS lexing rules for strings
// (including escapes), numbers, identifiers, comments and punctuators. Known gap:
// regex literals (/.../) are lexed as division operators, so a $where that embeds
// user input inside a regex literal yields a different structure per input
// (a false positive, never a false negative).

const PUNCTUATORS = [
  '>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=', '-=',
  '*=', '/=', '%=', '&=', '|=', '^=', '**', '<<', '>>',
];

const isIdStart = (c) => /[A-Za-z_$\u0080-￿]/.test(c);
const isIdPart = (c) => /[A-Za-z0-9_$\u0080-￿]/.test(c);
const isDigit = (c) => c >= '0' && c <= '9';

function tokenize(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;

  while (i < n) {
    const c = src[i];

    // whitespace
    if (/\s/.test(c)) { i++; continue; }

    // comments are dropped: they never execute, and code they comment out
    // disappears from the token stream, which itself changes the structure
    if (c === '/' && src[i + 1] === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      if (end === -1) { tokens.push('COMMENT!'); break; }
      i = end + 2;
      continue;
    }

    // string literals, honoring backslash escapes
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      let closed = false;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === c) { closed = true; break; }
        // template substitutions contain code; treat them as structure-changing
        if (c === '`' && src[j] === '$' && src[j + 1] === '{') break;
        j++;
      }
      if (!closed) {
        tokens.push(c === '`' ? 'TPL!' : 'STR!');
        tokens.push(...tokenize(src.slice(j)));
        return tokens;
      }
      tokens.push(c === '`' ? 'TPL' : 'STR');
      i = j + 1;
      continue;
    }

    // numeric literals: 12, 1.5, .5, 1e9, 0x1f, 1_000, 10n
    if (isDigit(c) || (c === '.' && isDigit(src[i + 1] || ''))) {
      let j = i;
      if (c === '0' && /[xXoObB]/.test(src[i + 1] || '')) {
        j += 2;
        while (j < n && /[0-9a-fA-F_]/.test(src[j])) j++;
      } else {
        while (j < n && /[0-9_]/.test(src[j])) j++;
        if (src[j] === '.') { j++; while (j < n && /[0-9_]/.test(src[j])) j++; }
        if (/[eE]/.test(src[j] || '') && /[0-9+-]/.test(src[j + 1] || '')) {
          j += 2;
          while (j < n && isDigit(src[j])) j++;
        }
      }
      if (src[j] === 'n') j++;
      tokens.push('NUM');
      i = j;
      continue;
    }

    // identifiers and keywords (kept verbatim: they are structure, not data)
    if (isIdStart(c) || c === '\\') {
      let j = i + 1;
      while (j < n && (isIdPart(src[j]) || src[j] === '\\')) j++;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }

    const p = PUNCTUATORS.find((op) => src.startsWith(op, i));
    if (p) { tokens.push(p); i += p.length; continue; }

    tokens.push(c); // single-char punctuator or anything else
    i++;
  }
  return tokens;
}

function jsStructure(src) {
  return tokenize(String(src)).join(' ');
}

module.exports = { jsStructure, tokenize };
