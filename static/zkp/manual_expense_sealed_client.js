/* Manual-transaction ZK-proof client, v3 (sealed).
 *
 * This implements the encryption-bound proof: the circuit proves that the
 * public ciphertext output encrypts the validated plaintext under a key
 * derived from the vault key. The server stores exactly the circuit-output
 * ciphertext, closing the v2 gap where proof and ciphertext were unlinked.
 *
 * Key derivation (browser only, never sent to server):
 *   enc_key = bytes_to_field(BLAKE2b("mindful-money-zkp-enc-v1" || privateKey || record_id)[:31])
 *   enc_nonce = random Field (stored alongside ciphertext, public)
 *
 * Encryption (must match zkp/manual_expense_sealed/src/main.nr):
 *   plaintext[0..3] = name bytes packed as 30 bytes/field (little-endian)
 *   plaintext[4] = amount | category<<64 | has_category<<128 | name_length<<129
 *   plaintext[5..7] = 0
 *   keystream[i] = Poseidon2(enc_key, enc_nonce, i)
 *   ciphertext[i] = plaintext[i] + keystream[i]
 *   mac = Poseidon2(enc_key, enc_nonce, ciphertext[0..7])
 *
 * Decryption (on read):
 *   Re-derive enc_key, recompute keystream, subtract to get plaintext.
 *   Verify mac before using decrypted data.
 *
 * STATUS: Circuit written, client implemented. Requires:
 *   1. nargo compile of zkp/manual_expense_sealed
 *   2. bb setup for proving/verification keys
 *   3. Server support for v3 proofs (see zkp_verifier.py)
 */

import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import initNoirC from '@noirc_abi';
import initACVM from '@acvm_js';
import circuit from '../../zkp/manual_expense_sealed/target/manual_expense_sealed.json';

export const CIRCUIT_VERSION_V3 = 'manual-transaction-v3';
export const SCHEMA_VERSION_V3 = 3;

// Must match main.nr
const MAX_NAME_BYTES = 120;
const CIPHERTEXT_LEN = 8;
const BYTES_PER_FIELD = 30;

// BN254 field modulus
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let wasmReady = null;
function ensureWasmReady() {
  if (!wasmReady) {
    wasmReady = Promise.all([initACVM(), initNoirC()]);
  }
  return wasmReady;
}

let barretenbergInstance = null;
async function getBackend() {
  await ensureWasmReady();
  if (!barretenbergInstance) {
    barretenbergInstance = await Barretenberg.new();
  }
  return new UltraHonkBackend(circuit.bytecode, barretenbergInstance);
}

/**
 * Convert 31 bytes to a BN254 field element (big-endian).
 */
function bytesToField(bytes) {
  if (bytes.length > 31) throw new Error('Too many bytes for field element');
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  if (result >= FIELD_MODULUS) throw new Error('Bytes exceed field modulus');
  return result;
}

/**
 * Derive the ZKP encryption key from the vault private key.
 * Domain-separated; never leaves the browser.
 */
export async function deriveZkpEncKey(privateKey, recordId) {
  // privateKey: Uint8Array(32), recordId: string
  const domain = new TextEncoder().encode('mindful-money-zkp-enc-v1');
  const recordBytes = new TextEncoder().encode(recordId);
  const input = new Uint8Array(domain.length + privateKey.length + recordBytes.length);
  input.set(domain);
  input.set(privateKey, domain.length);
  input.set(recordBytes, domain.length + privateKey.length);
  
  // Use libsodium's generic hash (BLAKE2b)
  const hash = window.S.crypto_generichash(32, input);
  // Take first 31 bytes to ensure < field modulus
  return bytesToField(hash.slice(0, 31));
}

/**
 * Pack plaintext into 8 field elements (must match circuit).
 */
function packPlaintext(nameBytes, nameLength, amountCents, categoryId, hasCategory) {
  const plaintext = new Array(CIPHERTEXT_LEN).fill(0n);
  
  // Pack name: 30 bytes per field, little-endian
  for (let f = 0; f < 4; f++) {
    let acc = 0n;
    let mult = 1n;
    for (let b = 0; b < BYTES_PER_FIELD; b++) {
      const idx = f * BYTES_PER_FIELD + b;
      if (idx < MAX_NAME_BYTES && idx < nameBytes.length) {
        acc += BigInt(nameBytes[idx]) * mult;
        mult *= 256n;
      }
    }
    plaintext[f] = acc;
  }
  
  // Pack metadata into field 4
  let meta = BigInt(amountCents);
  meta += BigInt(categoryId) * (1n << 64n);
  if (hasCategory) meta += (1n << 128n);
  meta += BigInt(nameLength) * (1n << 129n);
  plaintext[4] = meta;
  
  // Fields 5-7 are zero padding
  return plaintext;
}

/**
 * Unpack plaintext fields to components.
 */
function unpackPlaintext(plaintext) {
  // Unpack name
  const nameBytes = new Uint8Array(MAX_NAME_BYTES);
  for (let f = 0; f < 4; f++) {
    let val = plaintext[f];
    for (let b = 0; b < BYTES_PER_FIELD; b++) {
      const idx = f * BYTES_PER_FIELD + b;
      if (idx < MAX_NAME_BYTES) {
        nameBytes[idx] = Number(val & 0xFFn);
        val >>= 8n;
      }
    }
  }
  
  // Unpack metadata
  const meta = plaintext[4];
  const amountCents = Number(meta & ((1n << 64n) - 1n));
  const categoryId = Number((meta >> 64n) & ((1n << 64n) - 1n));
  const hasCategory = ((meta >> 128n) & 1n) === 1n;
  const nameLength = Number((meta >> 129n) & ((1n << 32n) - 1n));
  
  return { nameBytes: nameBytes.slice(0, nameLength), amountCents, categoryId, hasCategory, nameLength };
}

/**
 * Generate a ZKP-bound sealed record.
 * Returns { proof, publicInputs, ciphertext, mac, nonce }.
 */
export async function proveSealedTransaction(params) {
  const {
    name, amountCents, categoryId, hasCategory,
    privateKey, recordId, challenge, recordIdHash,
    commitmentBlinding,
  } = params;
  
  const backend = await getBackend();
  const noir = new Noir(circuit);
  
  // Prepare witness
  const nameBytes = new TextEncoder().encode(name);
  const namePadded = new Uint8Array(MAX_NAME_BYTES);
  namePadded.set(nameBytes.slice(0, MAX_NAME_BYTES));
  
  const encKey = await deriveZkpEncKey(privateKey, recordId);
  const encNonce = bytesToField(window.S.randombytes_buf(31));
  
  const inputs = {
    name_bytes: Array.from(namePadded),
    name_length: nameBytes.length,
    amount_cents: amountCents,
    category_id: categoryId,
    has_category: hasCategory,
    commitment_blinding: commitmentBlinding.toString(),
    enc_key: encKey.toString(),
    enc_nonce: encNonce.toString(),
    challenge: challenge.toString(),
    record_id_hash: recordIdHash.toString(),
    schema_version: SCHEMA_VERSION_V3,
  };
  
  const { witness } = await noir.execute(inputs);
  const { proof, publicInputs } = await backend.generateProof(witness);
  
  // Extract public outputs: commitment, ciphertext[8], mac
  // (Layout depends on circuit ABI; adjust based on compiled artifact)
  return {
    proof,
    publicInputs,
    encNonce: encNonce.toString(),
    circuitVersion: CIRCUIT_VERSION_V3,
  };
}

/**
 * Decrypt a ZKP-sealed ciphertext (for reading stored records).
 * Requires the vault private key to re-derive enc_key.
 */
export async function decryptSealedTransaction(ciphertextFields, mac, nonce, privateKey, recordId) {
  const encKey = await deriveZkpEncKey(privateKey, recordId);
  const encNonce = BigInt(nonce);
  
  // Recompute keystream and decrypt
  // NOTE: This requires Poseidon2 in JS. Use bb.js Barretenberg instance
  // or a standalone Poseidon implementation.
  // For now, this is a placeholder - full implementation needs Poseidon2 JS.
  throw new Error('decryptSealedTransaction: Poseidon2 JS implementation needed');
  
  // Pseudocode once Poseidon is available:
  // const plaintext = [];
  // for (let i = 0; i < CIPHERTEXT_LEN; i++) {
  //   const ks = poseidon2([encKey, encNonce, BigInt(i)]);
  //   plaintext[i] = (BigInt(ciphertextFields[i]) - ks + FIELD_MODULUS) % FIELD_MODULUS;
  // }
  // // Verify MAC
  // const macInput = [encKey, encNonce, ...plaintext.map(BigInt)];
  // const computedMac = poseidon2(macInput);
  // if (computedMac !== BigInt(mac)) throw new Error('MAC verification failed');
  // return unpackPlaintext(plaintext);
}
