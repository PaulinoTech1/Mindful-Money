// Bug N: decrypted records with a missing or malformed shape are skipped and
// counted, never thrown on (static/app.js normalizeRecords).
// Run: node tests/record_shape.test.mjs
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const src = fs.readFileSync(new URL('../static/app.js', import.meta.url), 'utf8');
function extractFn(sig) {
  const start = src.indexOf(sig);
  assert.ok(start >= 0, 'missing ' + sig);
  let i = src.indexOf('{', src.indexOf(')', start)), depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(start, i + 1);
}
const ctx = {};
vm.runInNewContext(extractFn('function normalizeRecords(') + '\nthis.normalizeRecords = normalizeRecords;', ctx);
const normalizeRecords = (x) => JSON.parse(JSON.stringify(ctx.normalizeRecords(x)));

const good = (id, date) => ({ id, date, amount: -12.5, merchant: 'Shop' });
const input = [
  good('b', '2026-02-01'), good('a', '2026-01-01'),
  { id: 'x', amount: 1, merchant: 'No date' },                 // missing date
  { id: 'y', date: 20260101, amount: 1, merchant: 'Num date' }, // wrong type
  { id: 'z', date: 'yesterday', amount: 1, merchant: 'Bad' },   // malformed
  { id: 'w', date: '2026-01-02', amount: 'NaN', merchant: 'M' },// bad amount
  { id: 'v', date: '2026-01-02', amount: Infinity, merchant: 'M' },
  { date: '2026-01-02', amount: 1, merchant: 'no id' },
  { id: 'u', date: '2026-01-02', amount: 1 },                   // no merchant
  null, 'string', [1, 2],
];
let out;
assert.doesNotThrow(() => { out = normalizeRecords(input); });
assert.equal(out.skipped, 10);
assert.deepEqual(out.valid.map((t) => t.id), ['a', 'b'], 'valid records sorted by date');
const t = out.valid[0];
assert.equal(t.notes, ''); assert.deepEqual(t.tags, []); assert.deepEqual(t.splits, []);
assert.equal(t.is_transfer, false); assert.equal(t.fraud_status, '');

const coerced = normalizeRecords([{ ...good('c', '2026-03-03'), notes: 5, tags: 'x', splits: {}, fraud_status: 'weird', category: 7 }]);
assert.equal(coerced.skipped, 0);
assert.equal(coerced.valid[0].notes, ''); assert.deepEqual(coerced.valid[0].tags, []);
assert.equal(coerced.valid[0].fraud_status, ''); assert.equal(coerced.valid[0].category, '');

assert.deepEqual(normalizeRecords([]), { valid: [], skipped: 0 });

// Only key/decryption failures may be reported as a wrong passphrase.
const load = extractFn('async function load(');
assert.match(load, /err\.code = 'DECRYPT_FAILED'/);
assert.ok(!/localeCompare/.test(load), 'load() must not sort with a throwing comparator');
const unlock = extractFn('async function unlock(');
assert.match(unlock, /code === 'DECRYPT_FAILED'\) \$\('gateNote'\)\.textContent = 'Incorrect vault passphrase/);
assert.match(unlock, /not a passphrase problem/);
console.log('record_shape: all assertions passed');
