// Unit tests for the sealed-record padding format (static/app.js).
// Run: node tests/padding.test.mjs
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const src = fs.readFileSync(new URL('../static/app.js', import.meta.url), 'utf8');
function extractFn(name) {
  const start = src.indexOf('function ' + name + '(');
  assert.ok(start >= 0, 'missing ' + name);
  let i = src.indexOf('{', src.indexOf(')', start)), depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(start, i + 1);
}
function extractConst(name) {
  const m = src.match(new RegExp('const ' + name + ' = [^;]+;'));
  assert.ok(m, 'missing const ' + name);
  return m[0];
}
const code = ['PAD_BUCKETS', 'PAD_MAX', 'PAD_VERSION', 'PAD_TRAILER'].map(extractConst)
  .concat(['padPlaintext', '_unpadV2', '_isCanonicalJson', '_unpadLegacyV1', 'unpadPlaintext'].map(extractFn))
  .join('\n') + '\nthis.api = { padPlaintext, unpadPlaintext, PAD_BUCKETS, PAD_MAX, PAD_TRAILER };';
const ctx = { TextDecoder, Uint8Array, JSON, Error };
vm.createContext(ctx);
vm.runInContext(code, ctx);
const { padPlaintext, unpadPlaintext, PAD_BUCKETS, PAD_MAX, PAD_TRAILER } = ctx.api;

// The pre-2026-10-13 writer, verbatim, to produce legacy records.
function legacyPad(data) {
  let bucket = PAD_BUCKETS[PAD_BUCKETS.length - 1];
  for (const b of PAD_BUCKETS) { if (data.length <= b) { bucket = b; break; } }
  const padLen = bucket - data.length;
  const padded = new Uint8Array(bucket);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}
const enc = new TextEncoder();
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
// Canonical JSON (what seal() writes) of an exact byte length >= 8.
const jsonOfLen = (L, ch = 'x') => enc.encode('{"a":"' + ch.repeat(L - 8) + '"}');

let n = 0;
// 1. v2 round trip for every length 0..max, arbitrary bytes, bucket sizes only.
const maxData = PAD_MAX - PAD_TRAILER;
for (let L = 0; L <= maxData; L++) {
  const data = new Uint8Array(L);
  for (let i = 0; i < L; i++) data[i] = (i * 31 + L) & 0xff;
  const p = padPlaintext(data);
  assert.ok(PAD_BUCKETS.includes(p.length), `bucket for ${L}`);
  assert.ok(p.length >= L + PAD_TRAILER);
  assert.ok(eq(unpadPlaintext(p), data), `v2 round trip ${L}`);
  n++;
}
// Bucket edges choose the expected bucket.
for (const b of PAD_BUCKETS) {
  assert.equal(padPlaintext(new Uint8Array(b - PAD_TRAILER)).length, b, `edge fits ${b}`);
  if (b !== PAD_MAX) assert.equal(padPlaintext(new Uint8Array(b - PAD_TRAILER + 1)).length, PAD_BUCKETS[PAD_BUCKETS.indexOf(b) + 1]);
}
// 8188..8192 and above: rejected cleanly (new max is PAD_MAX - 5).
for (let L = maxData + 1; L <= PAD_MAX + 1; L++) {
  assert.throws(() => padPlaintext(new Uint8Array(L)), /Record too large/);
}

// 2. Legacy records written by the old writer still read, for every JSON
//    length 8..8192, including the ones the old reader broke (pad >= 256).
let legacyOk = 0;
for (let L = 8; L <= PAD_MAX; L++) {
  for (const ch of ['x', '}', ' ']) {   // '}' (0x7d) and ' ' stress the run heuristic
    if (ch !== 'x' && L % 97 !== 0) continue;
    const data = jsonOfLen(L, ch);
    const out = unpadPlaintext(legacyPad(data));
    assert.ok(eq(out, data), `legacy ${L} ${JSON.stringify(ch)}`);
    legacyOk++;
  }
}
// A legacy record whose pad byte equals '}' (pad length 125 or 381 ...).
for (const L of [512 - 125, 512 - 381, 1024 - 637]) {
  const data = jsonOfLen(L);
  assert.ok(eq(unpadPlaintext(legacyPad(data)), data), `legacy brace pad ${L}`);
}

// 3. Malformed input rejected cleanly.
assert.throws(() => unpadPlaintext(new Uint8Array(0)), /Invalid padded length/);
assert.throws(() => unpadPlaintext(new Uint8Array(100)), /Invalid padded length/);
assert.throws(() => unpadPlaintext('not bytes'), /Invalid padded length/);
assert.throws(() => unpadPlaintext(new Uint8Array(512)), /Invalid padding/);           // all zero
assert.throws(() => unpadPlaintext(new Uint8Array(512).fill(7)), /Invalid padding/);  // no JSON
{ const p = padPlaintext(enc.encode('{"ok":1}')); p[p.length - 10] = 1;               // dirty fill
  assert.throws(() => unpadPlaintext(p), /Invalid padding/); }
{ const p = padPlaintext(enc.encode('{"ok":1}')); p[p.length - 2] = 0xff;             // bad length
  assert.throws(() => unpadPlaintext(p), /Invalid padding/); }
{ const bad = legacyPad(enc.encode('{"a":"\xff"}')); bad[7] = 0xff;                    // invalid UTF-8
  assert.throws(() => unpadPlaintext(bad), /Invalid padding/); }

console.log(`padding: ${n} v2 round trips, ${legacyOk} legacy reads, malformed cases rejected`);
