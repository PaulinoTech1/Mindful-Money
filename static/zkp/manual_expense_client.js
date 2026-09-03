/* Manual-transaction ZK-proof client.
 *
 * STATUS: compiled, bundled, and exercised with a real bb.js proof that
 * the native bb 5.1.0 CLI also verified. It is intentionally NOT wired
 * into static/app.js's live "Add transaction" flow yet; see
 * ../../zkp/README.md for the alpha feature-gating and bundle-size note.
 *
 * The API calls and data formats below are pinned to Noir
 * 1.0.0-beta.26 and @aztec/bb.js 5.1.0. In this version the backend
 * constructor requires the shared Barretenberg instance, and
 * generateProof() returns proof bytes and public inputs separately.
 *
 * Trust boundary: everything below runs in the browser. Flask (see
 * app.py's /api/zkp/challenge and /api/records/manual) never receives
 * anything from here except challenge_id, blind_index, sealed (opaque
 * ciphertext), commitment (a public Poseidon2 output -- not a secret),
 * proof bytes, and the four public proof inputs. Flask reconstructs those
 * inputs from server-owned challenge/record/schema context plus the
 * commitment. name, amount_cents, category_id, and commitment_blinding
 * never leave this file. Do not log any of `inputs` below.
 */

import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import initNoirC from '@noir-lang/noirc_abi';
import initACVM from '@noir-lang/acvm_js';
import acvmWasmUrl from '@noir-lang/acvm_js/web/acvm_js_bg.wasm?url';
import noircWasmUrl from '@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url';
import circuit from '../../zkp/manual_expense/target/manual_expense.json';

export const CIRCUIT_VERSION = 'manual-transaction-v2';
export const SCHEMA_VERSION = 2;
const MAX_NAME_BYTES = 120;
// Order matters: flattened index == the circuit's category_id. Each type
// gets its own Other id so the commitment also binds income vs expense.
// Keep this in sync with static/app.js, zkp_verifier.py, and main.nr.
const CATEGORY_IDS_BY_TYPE = Object.freeze({
  expense: Object.freeze([
    'Housing', 'Groceries', 'Dining', 'Transport', 'Utilities', 'Subscriptions',
    'Shopping', 'Health & insurance', 'Investing', 'Other',
  ]),
  income: Object.freeze([
    'Salary', 'Freelance', 'Investment income', 'Refund', 'Gift', 'Other',
  ]),
});
// Same ASCII label as DOMAIN_SEPARATOR in main.nr. Recomputed
// here independently (not copy-pasted as a hex literal) so a future edit
// to the label can't silently desync the two without also changing this
// literal string.
const DOMAIN_SEPARATOR_LABEL = 'PAULINOTECH_MANUAL_TX_V2';

let wasmReady = null;
function ensureWasmReady() {
  if (!wasmReady) {
    wasmReady = Promise.all([initACVM(fetch(acvmWasmUrl)), initNoirC(fetch(noircWasmUrl))]);
  }
  return wasmReady;
}

let barretenbergInstance = null;
async function getBarretenberg() {
  if (!barretenbergInstance) barretenbergInstance = await Barretenberg.new();
  return barretenbergInstance;
}

function fieldFromLabel(label) {
  const bytes = new TextEncoder().encode(label);
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}
const DOMAIN_SEPARATOR = fieldFromLabel(DOMAIN_SEPARATOR_LABEL);

// ---- canonicalization -----------------------------------------------
// Mirrors main.nr's witness shape exactly. Does NOT re-implement
// validateTransactionName/Amount/Category from static/app.js -- callers must
// run those first. This only turns already-validated values into the
// circuit's fixed-size representation, and fails loudly (not silently)
// if a value somehow doesn't fit, rather than truncating or padding past
// what the circuit actually proves.

function nameToFixedBuffer(name) {
  const bytes = Array.from(new TextEncoder().encode(name.normalize('NFC')));
  if (bytes.length < 1 || bytes.length > MAX_NAME_BYTES) {
    // The UI's "1 to 120 characters" is a code-point bound
    // (validateTransactionName); this is a byte bound. Most names never hit
    // this gap, but multi-byte UTF-8 can -- see ../../zkp/README.md.
    throw new Error('Expense name does not fit the proof’s 120-byte bound.');
  }
  const padded = bytes.concat(Array(MAX_NAME_BYTES - bytes.length).fill(0));
  return { name_bytes: padded, name_length: bytes.length };
}

// Takes the ORIGINAL validated decimal string (e.g. "12.34"), not the
// Number validateTransactionAmount() also returns -- deriving cents from a
// JS Number would reintroduce exactly the binary-float risk this design
// exists to avoid.
function amountStringToCents(rawAmountString) {
  const match = /^(\d{1,9})(?:\.(\d{1,2}))?$/.exec(rawAmountString.trim());
  if (!match) throw new Error('Amount is not a validated decimal string.');
  const whole = BigInt(match[1]);
  const frac = (match[2] || '').padEnd(2, '0');
  const cents = whole * 100n + BigInt(frac);
  if (cents <= 0n) throw new Error('Amount must be greater than zero.');
  return cents;
}

function categoryToWitness(categoryNameOrUndefined, transactionType) {
  if (categoryNameOrUndefined === undefined) return { category_id: 0, has_category: false };
  if (!Object.hasOwn(CATEGORY_IDS_BY_TYPE, transactionType)) throw new Error('Unknown transaction type.');
  const localId = CATEGORY_IDS_BY_TYPE[transactionType].indexOf(categoryNameOrUndefined);
  if (localId < 0) throw new Error(`Unknown ${transactionType} category.`);
  const id = transactionType === 'income' ? CATEGORY_IDS_BY_TYPE.expense.length + localId : localId;
  return { category_id: id, has_category: true };
}

// 128 bits of browser CSPRNG entropy, matching this design's documented
// minimum -- see the project delivery report, "Circuit design" (blinding).
function randomBlindingField() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

function hexToField(hex) {
  return hex.startsWith('0x') ? hex : `0x${hex}`;
}

function bytesToHex(bytes) {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// BN254 scalar field modulus used by Noir and UltraHonk. Reject rather
// than reduce non-canonical values: two encodings must never name the
// same public input at the API boundary.
const FIELD_MODULUS = BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001');

function normalizeFieldHex(value) {
  const integer = BigInt(value);
  if (integer < 0n || integer >= FIELD_MODULUS) {
    throw new Error('Value is not a canonical BN254 field element.');
  }
  return `0x${integer.toString(16).padStart(64, '0')}`;
}

function fieldToBytes(value) {
  const hex = normalizeFieldHex(value).slice(2);
  return Uint8Array.from(hex.match(/../g).map((byte) => Number.parseInt(byte, 16)));
}

/**
 * Compute the same Poseidon2 commitment main.nr's `main` returns,
 * independent of running the circuit. Used both before proving (to
 * supply the `commitment` public input the circuit checks) and by
 * verifyStoredRecord() below (to re-check a decrypted record's stored
 * commitment on every read, without re-proving anything).
 *
 * Preimage order MUST exactly match main.nr's `preimage` array -- this is
 * the one place that ordering is duplicated outside the circuit; a
 * mismatch here would make every proof fail closed (safe) rather than
 * silently verify the wrong thing, but keep the two in sync deliberately.
 */
async function computeCommitment({
  nameBytes, nameLength, amountCents, categoryId, hasCategory,
  blinding, challenge, recordIdHash,
}) {
  const bb = await getBarretenberg();
  const preimage = [
    DOMAIN_SEPARATOR,
    hexToField(challenge),
    hexToField(recordIdHash),
    `0x${SCHEMA_VERSION.toString(16)}`,
    blinding,
    `0x${amountCents.toString(16)}`,
    `0x${categoryId.toString(16)}`,
    hasCategory ? '0x1' : '0x0',
    `0x${nameLength.toString(16)}`,
    ...nameBytes.map((b) => `0x${b.toString(16)}`),
  ];
  // Barretenberg 5.1's generated RPC API accepts `{ inputs: Uint8Array[] }`
  // and returns `{ hash: Uint8Array }`. Both use 32-byte big-endian field
  // encodings, the same encoding emitted in ProofData.publicInputs.
  const result = await bb.poseidon2Hash({ inputs: preimage.map(fieldToBytes) });
  return normalizeFieldHex(`0x${bytesToHex(result.hash)}`);
}

/** Thin wrapper over POST /api/zkp/challenge -- see app.py. `apiFetch`
 * is static/app.js's existing `api()` helper, passed in rather than
 * imported, so this module has no hard dependency on app.js's globals. */
export async function requestChallenge(apiFetch) {
  return apiFetch('/api/zkp/challenge', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ purpose: 'manual_expense_create' }),
  });
}

/**
 * Full prove step for one manual transaction. `validated` = the output of
 * static/app.js's transaction validators, PLUS the original raw amount string (needed
 * for exact-decimal cents conversion -- see amountStringToCents).
 * `challengeResponse` = requestChallenge()'s result.
 *
 * Returns { commitment, blinding, proof, publicInputs, publicContext }
 * ready to submit
 * to POST /api/records/manual alongside blind_index/sealed (produced by
 * static/app.js's existing blindIndex()/seal(), unchanged) -- `blinding`
 * must be included in the sealed plaintext record (see
 * ../../zkp/README.md, "AES-GCM record" / this app's sealed-box
 * equivalent) so a legitimate client can recompute the commitment later.
 */
export async function proveManualTransaction(challengeResponse, validated) {
  await ensureWasmReady();

  const { name_bytes, name_length } = nameToFixedBuffer(validated.name);
  const cents = amountStringToCents(validated.rawAmount);
  const { category_id, has_category } = categoryToWitness(validated.category, validated.transactionType);
  const blinding = randomBlindingField();
  const challenge = hexToField(challengeResponse.challenge);
  const recordIdHash = hexToField(challengeResponse.record_id);

  const inputs = {
    name_bytes, name_length,
    amount_cents: cents.toString(),
    category_id: category_id.toString(),
    has_category,
    commitment_blinding: blinding,
    challenge, record_id_hash: recordIdHash,
    schema_version: SCHEMA_VERSION.toString(),
  };

  const noir = new Noir(circuit);
  const bb = await getBarretenberg();
  const backend = new UltraHonkBackend(circuit.bytecode, bb);
  const { witness, returnValue } = await noir.execute(inputs);
  const commitmentField = normalizeFieldHex(returnValue);
  const proof = await backend.generateProof(witness);
  const expectedPublicInputs = [
    normalizeFieldHex(challenge),
    normalizeFieldHex(recordIdHash),
    normalizeFieldHex(SCHEMA_VERSION),
    commitmentField,
  ];
  const proofPublicInputs = proof.publicInputs.map(normalizeFieldHex);
  if (
    proofPublicInputs.length !== expectedPublicInputs.length
    || proofPublicInputs.some((value, index) => value !== expectedPublicInputs[index])
  ) {
    throw new Error('Proof public inputs do not match the requested record context.');
  }
  const verifiedLocally = await backend.verifyProof(proof);
  if (!verifiedLocally) {
    // Should be unreachable if the constraints above are satisfiable --
    // a local self-check failing means something in this file's witness
    // construction is wrong, not that the user's input was invalid.
    throw new Error('Local proof self-check failed.');
  }

  return {
    commitment: commitmentField.slice(2),
    blinding,
    proof: bytesToHex(proof.proof),
    publicInputs: proofPublicInputs,
    // Encrypt this context with the record. It lets the browser
    // recompute the commitment after decryption without revealing the
    // private transaction fields or the blinding factor to Flask.
    publicContext: {
      challenge: challengeResponse.challenge,
      record_id: challengeResponse.record_id,
      schema_version: SCHEMA_VERSION,
    },
  };
}

// Backward-compatible export name for callers that imported the v1 module.
export const proveManualExpense = proveManualTransaction;

/**
 * Client retrieval verification (see ../../zkp/README.md). Call this
 * after decrypting a manual-transaction record and BEFORE rendering it.
 * Recomputes the commitment from the decrypted plaintext (which must
 * include `commitment_blinding`, per proveManualExpense's contract) and
 * compares it against the record's stored `commitment`. On any mismatch,
 * the caller MUST treat the record as an integrity failure: do not
 * render it, do not silently repair it. This is the layer that would
 * catch the proof/ciphertext-mismatch scenario documented in
 * ../../zkp/README.md and test_zkp_server.py -- Flask cannot detect it at
 * ingestion time, but a legitimate client detects it here on read.
 */
export async function verifyStoredRecord(decryptedRecord, storedCommitmentHex, publicContext) {
  const name = nameToFixedBuffer(decryptedRecord.merchant);
  const category = categoryToWitness(decryptedRecord.category, decryptedRecord.transaction_type);
  const recomputed = await computeCommitment({
    nameBytes: name.name_bytes,
    nameLength: name.name_length,
    amountCents: amountStringToCents(Math.abs(decryptedRecord.amount).toFixed(2)),
    categoryId: category.category_id,
    hasCategory: category.has_category,
    blinding: hexToField(decryptedRecord.commitment_blinding),
    challenge: hexToField(publicContext.challenge),
    recordIdHash: hexToField(publicContext.record_id),
  });
  const normalize = (h) => h.replace(/^0x/, '').toLowerCase();
  return normalize(recomputed) === normalize(storedCommitmentHex);
}
