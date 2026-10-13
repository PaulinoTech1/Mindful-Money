// Bulk uploads are chunked by count and bytes (static/app.js).
// Run: node tests/upload_chunking.test.mjs
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
const consts = ['UPLOAD_MAX_RECORDS', 'UPLOAD_MAX_BYTES', 'UPLOAD_RATE_RETRIES'].map(n => src.match(new RegExp('const ' + n + ' = [^;]+;'))[0]);
// Server limits, read from app.py defaults so the test tracks them.
const py = fs.readFileSync(new URL('../app.py', import.meta.url), 'utf8');
const SERVER_MAX_RECORDS = Number(py.match(/VAULT_MAX_RECORDS_PER_BATCH", "(\d+)"/)[1]);
const SERVER_MAX_HEX = Number(py.match(/VAULT_MAX_SEALED_HEX_LENGTH", "(\d+)"/)[1]);
const SERVER_MAX_BYTES = 8 * 1024 * 1024;
assert.ok(/VAULT_MAX_REQUEST_BYTES", str\(8 \* 1024 \* 1024\)/.test(py));

const requests = [];
const waits = [];
let fail429 = 0;  // number of upcoming requests to reject with 429
const ctx = {
  JSON, Error, Math,
  sleepMs: async (ms) => { waits.push(ms); },
  apiFetch: async (path, opts) => {
    if (fail429 > 0) {
      fail429--;
      const e = new Error('Request rate limit exceeded'); e.status = 429; e.retryAfter = 17; throw e;
    }
    const body = opts.body;
    const parsed = JSON.parse(body);
    assert.equal(path, '/api/records');
    assert.ok(Buffer.byteLength(body) <= SERVER_MAX_BYTES, 'request over server byte limit');
    assert.ok(parsed.records.length <= SERVER_MAX_RECORDS, 'request over server record limit');
    requests.push({ n: parsed.records.length, bytes: Buffer.byteLength(body), records: parsed.records });
    return { stored: parsed.records.length };
  },
};
vm.createContext(ctx);
vm.runInContext(['const api = apiFetch;', ...consts, extractFn('function chunkSealedRecords('),
  extractFn('async function uploadSealedRecords(')].join('\n') +
  '\nthis.f = { chunkSealedRecords, uploadSealedRecords, UPLOAD_MAX_RECORDS, UPLOAD_MAX_BYTES, UPLOAD_RATE_RETRIES };', ctx);
const { uploadSealedRecords, chunkSealedRecords, UPLOAD_MAX_RECORDS } = ctx.f;

const hex = (i, len) => (i.toString(16).padStart(8, '0') + 'a'.repeat(len)).slice(0, len);
// 1. 1,200 near-max records (worst case): several chunks, all under limits, order kept.
const big = Array.from({ length: 1200 }, (_, i) => ({ blind_index: hex(i, 64), sealed: hex(i, SERVER_MAX_HEX) }));
let progress = 0;
const nChunks = await uploadSealedRecords(big, (done) => { progress = done; });
assert.ok(nChunks >= 4, 'expected multiple chunks, got ' + nChunks);
assert.equal(progress, 1200);
const flat = requests.flatMap(r => r.records);
assert.equal(flat.length, 1200);
assert.ok(flat.every((r, i) => r.blind_index === big[i].blind_index && r.sealed === big[i].sealed));
const maxBytes = Math.max(...requests.map(r => r.bytes));
// 2. Many small records: chunked by count only.
requests.length = 0;
const small = Array.from({ length: 1201 }, (_, i) => ({ blind_index: hex(i, 64), sealed: hex(i, 1120) }));
await uploadSealedRecords(small);
assert.deepEqual(requests.map(r => r.n), [UPLOAD_MAX_RECORDS, UPLOAD_MAX_RECORDS, 201]);
// 3. Edge cases.
assert.equal(chunkSealedRecords([]).length, 0);
assert.throws(() => chunkSealedRecords([{ blind_index: 'a', sealed: 'b'.repeat(7 * 1024 * 1024) }]), /exceeds/);
// 4. 429 on a chunk: waits Retry-After, retries the same chunk, no loss or duplicates.
requests.length = 0;
fail429 = 2;
await uploadSealedRecords(small);
assert.deepEqual(Array.from(waits), [17000, 17000]);
assert.equal(requests.flatMap(r => r.records).length, 1201);
// 5. Persistent 429: gives up after UPLOAD_RATE_RETRIES retries and throws.
requests.length = 0; waits.length = 0;
fail429 = 100;
await assert.rejects(uploadSealedRecords(small), /rate limit/);
assert.equal(waits.length, ctx.f.UPLOAD_RATE_RETRIES);
assert.equal(requests.length, 0);
fail429 = 0;
console.log(`upload_chunking: 1200 near-max records in ${nChunks} chunks (largest ${maxBytes} bytes), count chunking ok, 429 retry ok`);
