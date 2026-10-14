/* Manual-transaction ZK proof v4 browser client (key-bound).
 *
 * STATUS: implemented and tested in Node (tests/zkp_v4_client.test.mjs) with
 * the real compiled circuit; NOT wired into static/app.js yet. The server
 * accepts v4 proofs only from vaults that enrolled a key commitment. See
 * docs/ZKP_BINDING.md.
 *
 * Trust boundary: the vault private key and zk_root stay in this page.
 * Flask receives only: key_commitment (once, at enrollment), challenge_id,
 * blind_index, proof bytes and the proof's public inputs. Flask fills every
 * public input it can (challenge, record id, schema, key_commitment,
 * vault_salt) from its own rows and builds the stored record from the
 * proven ciphertext outputs.
 */

import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import initNoirC from '@noir-lang/noirc_abi';
import initACVM from '@noir-lang/acvm_js';
import acvmWasmUrl from '@noir-lang/acvm_js/web/acvm_js_bg.wasm?url';
import noircWasmUrl from '@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url';
import circuit from '../../zkp/manual_expense_v4/target/manual_expense_v4.json';
import {
  SCHEMA_VERSION_V4, fieldHex, poseidon2From, deriveZkRoot, keyCommitment, nonceFor,
  nameToFixedBuffer, amountStringToCents, categoryToWitness, decryptV4,
} from './manual_expense_v4_core.js';

export { CIRCUIT_VERSION_V4, deriveZkRoot } from './manual_expense_v4_core.js';

let wasmReady = null;
function ensureWasmReady() {
  if (!wasmReady) wasmReady = Promise.all([initACVM(fetch(acvmWasmUrl)), initNoirC(fetch(noircWasmUrl))]);
  return wasmReady;
}
let bbInstance = null;
async function getBarretenberg() {
  if (!bbInstance) bbInstance = await Barretenberg.new();
  return bbInstance;
}

function randomBlindingField() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return fieldHex(BigInt(`0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`));
}

/**
 * One-time enrollment of this vault's key commitment. Both calls require a
 * recent passkey assertion (step-up). Returns { registered: true }.
 * `generichash` defaults to libsodium's crypto_generichash on window.S.
 */
export async function enrollKeyCommitment(apiFetch, privateKey, generichash = (n, m) => window.S.crypto_generichash(n, m)) {
  const p2 = poseidon2From(await getBarretenberg());
  const { vault_salt: salt } = await apiFetch('/api/zkp/key-commitment/salt', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  const root = deriveZkRoot(privateKey, generichash);
  const commitment = await keyCommitment(p2, root, BigInt(salt));
  return apiFetch('/api/zkp/key-commitment', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key_commitment: fieldHex(commitment).slice(2) }),
  });
}

/**
 * Prove one manual transaction. `challenge` is POST /api/zkp/challenge's
 * response (includes this vault's key_commitment and vault_salt). Returns
 * the body fields for POST /api/records/manual minus blind_index.
 */
export async function proveManualTransactionV4(challenge, validated, zkRoot) {
  await ensureWasmReady();
  const bb = await getBarretenberg();
  const p2 = poseidon2From(bb);
  const salt = BigInt(`0x${challenge.vault_salt}`);
  const registered = BigInt(`0x${challenge.key_commitment}`);
  // Fail early (and without a wasted proof) if this page holds a different key.
  if ((await keyCommitment(p2, zkRoot, salt)) !== registered) throw new Error('This vault key does not match the registered ZK key commitment.');
  const rid = BigInt(`0x${challenge.record_id}`);
  const { name_bytes, name_length } = nameToFixedBuffer(validated.name);
  const cents = amountStringToCents(validated.rawAmount);
  const { category_id, has_category } = categoryToWitness(validated.category, validated.transactionType);
  const inputs = {
    name_bytes, name_length,
    amount_cents: cents.toString(), category_id: category_id.toString(), has_category,
    commitment_blinding: randomBlindingField(),
    zk_root: fieldHex(zkRoot),
    enc_nonce: fieldHex(await nonceFor(p2, rid)),
    challenge: fieldHex(BigInt(`0x${challenge.challenge}`)),
    record_id_hash: fieldHex(rid),
    schema_version: SCHEMA_VERSION_V4.toString(),
    key_commitment: fieldHex(registered),
    vault_salt: fieldHex(salt),
  };
  const noir = new Noir(circuit);
  const backend = new UltraHonkBackend(circuit.bytecode, bb);
  const { witness } = await noir.execute(inputs);
  const proof = await backend.generateProof(witness);
  if (!(await backend.verifyProof(proof))) throw new Error('Local proof self-check failed.');
  return {
    challenge_id: challenge.challenge_id,
    proof: Array.from(proof.proof, (b) => b.toString(16).padStart(2, '0')).join(''),
    public_inputs: proof.publicInputs.map(fieldHex),
  };
}

/** Decrypt a stored v4 record (`sealed` from GET /api/records). */
export async function decryptManualTransactionV4(sealedHex, zkRoot) {
  return decryptV4(poseidon2From(await getBarretenberg()), sealedHex, zkRoot);
}
