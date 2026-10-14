// Node test for the v4 client core against the REAL compiled circuit.
//   cd static/zkp && npm ci && npm run test:v4
// Checks: libsodium BLAKE2b zk_root derivation; bb.js Poseidon2 equals the
// circuit's (nargo fixture values); honest proof verifies with 15 public
// inputs in the documented order; the stored record decrypts and
// authenticates; a random key cannot produce a witness; tampering or a
// wrong key fails decryption.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import Module from 'node:module';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import {
  deriveZkRoot, poseidon2From, keyCommitment, nonceFor, encKey, fieldHex, pack, nameToFixedBuffer,
  decryptV4, encryptV4, SCHEMA_VERSION_V4,
} from './manual_expense_v4_core.js';

const require = createRequire(import.meta.url);
const origResolve = Module._resolveFilename;
Module._resolveFilename = function (r, ...a) {
  if (r === 'libsodium-sumo' || r === 'libsodium') return require.resolve('../vendor/libsodium-sumo.js');
  return origResolve.call(this, r, ...a);
};
const sodium = require('../vendor/libsodium-wrappers.js');
await sodium.ready;

const circuit = JSON.parse(await readFile(new URL('../../zkp/manual_expense_v4/target/manual_expense_v4.json', import.meta.url), 'utf8'));
const bb = await Barretenberg.new();
const p2 = poseidon2From(bb);
let passed = 0;
const ok = (msg) => { passed += 1; console.log(`ok - ${msg}`); };

try {
  // 1. zk_root derivation (expected value computed with Python hashlib.blake2b(digest_size=32)).
  const privateKey = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const keyCopy = privateKey.slice();
  const root = deriveZkRoot(privateKey, sodium.crypto_generichash);
  assert.equal(root, 0xbcd6efac95e46281f6ebcf35427f370a0aee702f43cfb4510b6c2377e6b928n);
  assert.deepEqual(privateKey, keyCopy, 'private key must not be modified');
  ok('zk_root = BLAKE2b-256("mm-zkp-root-v1" || key)[0..31]');

  // 2. bb.js Poseidon2 matches the circuit (values printed by nargo test print_fixture).
  const ROOT = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdn;
  const SALT = 0x55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55n;
  assert.equal(fieldHex(await keyCommitment(p2, ROOT, SALT)), '0x0c83c98feb59e793295da3c820c6ef508319104f9f57fefd1ed8c6cae14a501e');
  assert.equal(fieldHex(await nonceFor(p2, 222n)), '0x09e8735df14daefa36f36583724339de52d98e6b87a2037c9f2415e071920451');
  ok('bb.js Poseidon2 equals Noir Poseidon2 (key commitment and nonce fixtures)');

  // 3. Honest proof with the derived root.
  const salt = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdn;
  const rid = 0xa1b2c3d4e5f60718293a4b5c6d7e8f90n; // 16 bytes, as the server issues
  const challenge = 0x0badc0ffeen;
  const commitment = await keyCommitment(p2, root, salt);
  const { name_bytes, name_length } = nameToFixedBuffer('Café run');
  const inputs = (zkRoot) => ({
    name_bytes, name_length, amount_cents: '4599', category_id: '11', has_category: true,
    commitment_blinding: '0x33', zk_root: fieldHex(zkRoot), enc_nonce: fieldHex(0n),
    challenge: fieldHex(challenge), record_id_hash: fieldHex(rid), schema_version: String(SCHEMA_VERSION_V4),
    key_commitment: fieldHex(commitment), vault_salt: fieldHex(salt),
  });
  const honest = inputs(root);
  honest.enc_nonce = fieldHex(await nonceFor(p2, rid));
  const noir = new Noir(circuit);
  const { witness } = await noir.execute(honest);
  const backend = new UltraHonkBackend(circuit.bytecode, bb);
  const proof = await backend.generateProof(witness);
  assert.ok(await backend.verifyProof(proof));
  const pub = proof.publicInputs.map((x) => BigInt(x));
  assert.equal(pub.length, 15);
  assert.deepEqual(pub.slice(0, 5), [challenge, rid, 4n, commitment, salt]);
  ok('honest proof verifies; 15 public inputs in documented order');

  // 4. Proven ciphertext equals the reference encryption and decrypts.
  const pt = pack(name_bytes, name_length, 4599n, 11n, true);
  const ref = await encryptV4(p2, root, rid, pt);
  assert.deepEqual(pub.slice(6, 14), ref.ct);
  assert.equal(pub[14], ref.mac);
  const sealed = rid.toString(16).padStart(32, '0') + pub.slice(6).map((v) => fieldHex(v).slice(2)).join('');
  const rec = await decryptV4(p2, sealed, root);
  assert.deepEqual(rec, { name: 'Café run', amount_cents: 4599n, category: 'Freelance', transaction_type: 'income' });
  ok('stored v4 record decrypts and authenticates');

  // 5. Negative: random key cannot satisfy the circuit.
  const randomRoot = BigInt(`0x${sodium.to_hex(sodium.randombytes_buf(31))}`);
  const bad = inputs(randomRoot);
  bad.enc_nonce = fieldHex(await nonceFor(p2, rid));
  await assert.rejects(noir.execute(bad));
  ok('random key: witness generation fails (no proof possible)');

  // 6. Negative: tampering and wrong key fail decryption.
  const flipped = sealed.slice(0, 40) + (sealed[40] === '0' ? '1' : '0') + sealed.slice(41);
  await assert.rejects(decryptV4(p2, flipped, root), /authentication failed|canonical/);
  await assert.rejects(decryptV4(p2, sealed, randomRoot), /authentication failed/);
  assert.notEqual(await encKey(p2, root, rid), await encKey(p2, root, rid + 1n));
  ok('tampered ciphertext and wrong key are rejected');
} finally {
  await bb.destroy();
}
console.log(`${passed} v4 client checks passed`);
