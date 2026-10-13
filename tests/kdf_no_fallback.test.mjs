// Unit test: a v3 vault must never silently fall back to v2 key derivation.
// Extracts checkKdfVersion, kdfParams and deriveKeys from static/app.js and
// runs them in a sandbox with a stubbed libsodium. No browser needed.
// Run: node tests/kdf_no_fallback.test.mjs
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const src = fs.readFileSync(new URL('../static/app.js', import.meta.url), 'utf8');
function extract(name) {
  const start = src.indexOf(name.startsWith('async') ? name : 'function ' + name);
  assert.ok(start >= 0, 'missing ' + name);
  let i = src.indexOf('{', start), depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(start, i + 1);
}
const code = [extract('checkKdfVersion'), extract('kdfParams'),
  extract('async function deriveKeys')].join('\n');

function makeSandbox(maxMem) {
  const calls = [];
  const S = {
    crypto_pwhash_ALG_ARGON2ID13: 2,
    crypto_pwhash_OPSLIMIT_MODERATE: 3, crypto_pwhash_MEMLIMIT_MODERATE: 268435456,
    crypto_pwhash_OPSLIMIT_INTERACTIVE: 2, crypto_pwhash_MEMLIMIT_INTERACTIVE: 67108864,
    crypto_pwhash(len, pass, salt, ops, mem) {
      calls.push({ ops, mem });
      if (mem > maxMem) throw new Error('Cannot allocate memory');
      return new Uint8Array(32).fill(ops);
    },
    crypto_box_seed_keypair(seed) { return { publicKey: seed, privateKey: seed }; },
  };
  const ctx = { S, calls, console: { error() {}, warn() {}, log() {} },
    getSalts: async () => ({ enc: new Uint8Array(16), idx: new Uint8Array(16) }),
    $: () => null, Math };
  vm.createContext(ctx);
  vm.runInContext(code, ctx);
  return ctx;
}

// 1. v3 with allocation failure: throws KDF_ALLOCATION_FAILED, never derives v2.
{
  const ctx = makeSandbox(1);
  await assert.rejects(ctx.deriveKeys('pw', 3), (e) => e.code === 'KDF_ALLOCATION_FAILED');
  assert.ok(ctx.calls.every(c => c.ops === 5), 'only v3 params may be attempted: ' + JSON.stringify(ctx.calls));
}
// 2. v3 success uses ops=5, 256MB and reports version 3.
{
  const ctx = makeSandbox(Infinity);
  const k = await ctx.deriveKeys('pw', 3);
  assert.equal(k.kdfVersion, 3);
  assert.ok(ctx.calls.every(c => c.ops === 5 && c.mem === 256 * 1024 * 1024));
}
// 3. Stored v2 vault still derives with v2 params.
{
  const ctx = makeSandbox(Infinity);
  const k = await ctx.deriveKeys('pw', 2);
  assert.equal(k.kdfVersion, 2);
  assert.ok(ctx.calls.every(c => c.ops === 3));
}
// 4. Unknown versions are rejected.
{
  const ctx = makeSandbox(Infinity);
  assert.throws(() => ctx.checkKdfVersion(4));
  assert.throws(() => ctx.checkKdfVersion('3'));
  assert.equal(ctx.checkKdfVersion(1), 1);
}
console.log('kdf_no_fallback: 4/4 passed');
