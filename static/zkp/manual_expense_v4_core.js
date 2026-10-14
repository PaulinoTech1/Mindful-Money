/* Manual-transaction ZK proof v4: pure helpers shared by the browser client
 * (manual_expense_v4_client.js) and the Node tests. No network, no DOM.
 *
 * Mirrors zkp/manual_expense_v4/src/main.nr exactly:
 *   zk_root        = BLAKE2b-256("mm-zkp-root-v1" || x25519 private key)[0..31]
 *   key_commitment = P2(DS_KEY, zk_root, vault_salt)
 *   enc_key        = P2(DS_ENC, zk_root, record_id_hash)
 *   enc_nonce      = P2(DS_NONCE, record_id_hash)
 *   ciphertext[i]  = plaintext[i] + P2(enc_key, enc_nonce, i)
 *   mac            = P2(DS_MAC, enc_key, enc_nonce, ciphertext[0..7])
 * where P2 is Barretenberg's Poseidon2 sponge hash (the same function Noir's
 * Poseidon2::hash(input, input.len()) computes; checked by
 * tests/zkp_v4_client.test.mjs against the compiled circuit).
 *
 * The private key and zk_root never leave the page. Callers must not log
 * any value produced here except public outputs.
 */

export const CIRCUIT_VERSION_V4 = 'manual-transaction-v4';
export const SCHEMA_VERSION_V4 = 4;
export const MAX_NAME_BYTES = 120;
export const CIPHERTEXT_LEN = 8;
export const RECORD_ID_BYTES = 16;
export const FIELD_MODULUS = BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001');
const BYTES_PER_FIELD = 30;
const ZK_ROOT_DOMAIN = 'mm-zkp-root-v1';

export function fieldFromLabel(label) {
  let v = 0n;
  for (const b of new TextEncoder().encode(label)) v = (v << 8n) | BigInt(b);
  return v;
}
export const DS_KEY = fieldFromLabel('MM_ZKP_KEY_COMMIT_V4');
export const DS_ENC = fieldFromLabel('MM_ZKP_ENC_KEY_V4');
export const DS_NONCE = fieldFromLabel('MM_ZKP_NONCE_V4');
export const DS_MAC = fieldFromLabel('MM_ZKP_MAC_V4');
export const DOMAIN_SEPARATOR = fieldFromLabel('PAULINOTECH_MANUAL_TX_V4');

const CATEGORY_IDS_BY_TYPE = Object.freeze({
  expense: Object.freeze(['Housing', 'Groceries', 'Dining', 'Transport', 'Utilities', 'Subscriptions',
    'Shopping', 'Health & insurance', 'Investing', 'Other']),
  income: Object.freeze(['Salary', 'Freelance', 'Investment income', 'Refund', 'Gift', 'Other']),
});

export function canonicalField(value) {
  const v = BigInt(value);
  if (v < 0n || v >= FIELD_MODULUS) throw new Error('Value is not a canonical BN254 field element.');
  return v;
}
export function fieldHex(value) {
  return `0x${canonicalField(value).toString(16).padStart(64, '0')}`;
}
export function fieldToBytes(value) {
  const hex = fieldHex(value).slice(2);
  return Uint8Array.from(hex.match(/../g).map((b) => Number.parseInt(b, 16)));
}
export function bytesToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}
function hexToBytes(hex) {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) throw new Error('Invalid hex.');
  return Uint8Array.from(hex.match(/../g) || [], (b) => Number.parseInt(b, 16));
}

/** Poseidon2 adapter over a Barretenberg instance (bb.js 5.1). */
export function poseidon2From(bb) {
  return async (inputs) => {
    const { hash } = await bb.poseidon2Hash({ inputs: inputs.map(fieldToBytes) });
    return bytesToBigInt(hash);
  };
}

/**
 * zk_root from the vault X25519 private key. `generichash(outlen, input)` is
 * libsodium's crypto_generichash (BLAKE2b). 31 bytes keep the value below the
 * BN254 modulus (248 bits of entropy). Intermediate buffers are zeroed;
 * the returned BigInt cannot be zeroed (JS limitation, see
 * docs/HARDENING_PROPOSALS.md R3).
 */
export function deriveZkRoot(privateKey, generichash) {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) throw new Error('Expected a 32-byte private key.');
  const domain = new TextEncoder().encode(ZK_ROOT_DOMAIN);
  const input = new Uint8Array(domain.length + privateKey.length);
  input.set(domain); input.set(privateKey, domain.length);
  const digest = generichash(32, input);
  const root = bytesToBigInt(digest.subarray(0, 31));
  input.fill(0); digest.fill(0);
  return root;
}

export const keyCommitment = (p2, root, salt) => p2([DS_KEY, root, salt]);
export const encKey = (p2, root, rid) => p2([DS_ENC, root, rid]);
export const nonceFor = (p2, rid) => p2([DS_NONCE, rid]);

// ---- witness canonicalization (same rules as the v2 client) ----
export function nameToFixedBuffer(name) {
  const bytes = Array.from(new TextEncoder().encode(name.normalize('NFC')));
  if (bytes.length < 1 || bytes.length > MAX_NAME_BYTES) throw new Error('Name does not fit the proof 120-byte bound.');
  return { name_bytes: bytes.concat(Array(MAX_NAME_BYTES - bytes.length).fill(0)), name_length: bytes.length };
}
export function amountStringToCents(raw) {
  const m = /^(\d{1,9})(?:\.(\d{1,2}))?$/.exec(String(raw).trim());
  if (!m) throw new Error('Amount is not a validated decimal string.');
  const cents = BigInt(m[1]) * 100n + BigInt((m[2] || '').padEnd(2, '0'));
  if (cents <= 0n) throw new Error('Amount must be greater than zero.');
  return cents;
}
export function categoryToWitness(category, transactionType) {
  if (category === undefined) return { category_id: 0, has_category: false };
  if (!Object.hasOwn(CATEGORY_IDS_BY_TYPE, transactionType)) throw new Error('Unknown transaction type.');
  const local = CATEGORY_IDS_BY_TYPE[transactionType].indexOf(category);
  if (local < 0) throw new Error(`Unknown ${transactionType} category.`);
  return { category_id: transactionType === 'income' ? CATEGORY_IDS_BY_TYPE.expense.length + local : local, has_category: true };
}
function categoryFromId(id, has) {
  if (!has) return { category: undefined, transaction_type: 'expense' };
  const n = CATEGORY_IDS_BY_TYPE.expense.length;
  if (id < n) return { category: CATEGORY_IDS_BY_TYPE.expense[id], transaction_type: 'expense' };
  if (id < n + CATEGORY_IDS_BY_TYPE.income.length) return { category: CATEGORY_IDS_BY_TYPE.income[id - n], transaction_type: 'income' };
  throw new Error('Unknown category id.');
}

const TWO64 = 1n << 64n;
const TWO128 = 1n << 128n;
const TWO129 = 1n << 129n;

export function pack(nameBytes, nameLength, amountCents, categoryId, hasCategory) {
  const pt = new Array(CIPHERTEXT_LEN).fill(0n);
  for (let f = 0; f < 4; f++) {
    let acc = 0n;
    for (let b = BYTES_PER_FIELD - 1; b >= 0; b--) acc = (acc << 8n) | BigInt(nameBytes[f * BYTES_PER_FIELD + b]);
    pt[f] = acc;
  }
  pt[4] = BigInt(amountCents) + BigInt(categoryId) * TWO64 + (hasCategory ? TWO128 : 0n) + BigInt(nameLength) * TWO129;
  return pt;
}

export function unpack(pt) {
  if (pt.length !== CIPHERTEXT_LEN || pt.slice(5).some((v) => v !== 0n)) throw new Error('Malformed plaintext.');
  const bytes = new Uint8Array(MAX_NAME_BYTES);
  for (let f = 0; f < 4; f++) {
    let v = pt[f];
    if (v >= (1n << 240n)) throw new Error('Malformed plaintext.');
    for (let b = 0; b < BYTES_PER_FIELD; b++) { bytes[f * BYTES_PER_FIELD + b] = Number(v & 0xffn); v >>= 8n; }
  }
  let meta = pt[4];
  const amount = meta % TWO64; meta /= TWO64;
  const categoryId = meta % TWO64; meta /= TWO64;
  const has = (meta & 1n) === 1n; meta >>= 1n;
  const nameLength = Number(meta);
  if (nameLength < 1 || nameLength > MAX_NAME_BYTES || bytes.subarray(nameLength).some((b) => b !== 0)) throw new Error('Malformed plaintext.');
  const name = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, nameLength));
  const { category, transaction_type } = categoryFromId(Number(categoryId), has);
  return { name, amount_cents: amount, category, transaction_type };
}

async function keystream(p2, key, nonce) {
  const ks = [];
  for (let i = 0; i < CIPHERTEXT_LEN; i++) ks.push(await p2([key, nonce, BigInt(i)]));
  return ks;
}
const macOf = (p2, key, nonce, ct) => p2([DS_MAC, key, nonce, ...ct]);

/**
 * Stored v4 record layout, built by the server from the verified proof's
 * public outputs: record_id (16 bytes) || ciphertext (8 x 32) || mac (32).
 */
export function parseSealedV4(sealedHex) {
  const bytes = hexToBytes(sealedHex);
  if (bytes.length !== RECORD_ID_BYTES + 32 * (CIPHERTEXT_LEN + 1)) throw new Error('Not a v4 record.');
  const rid = bytesToBigInt(bytes.subarray(0, RECORD_ID_BYTES));
  const ct = [];
  for (let i = 0; i < CIPHERTEXT_LEN; i++) ct.push(canonicalField(bytesToBigInt(bytes.subarray(RECORD_ID_BYTES + 32 * i, RECORD_ID_BYTES + 32 * (i + 1)))));
  const mac = canonicalField(bytesToBigInt(bytes.subarray(RECORD_ID_BYTES + 32 * CIPHERTEXT_LEN)));
  return { rid, ct, mac };
}

/** Decrypt and authenticate a stored v4 record. Throws on any mismatch. */
export async function decryptV4(p2, sealedHex, zkRoot) {
  const { rid, ct, mac } = parseSealedV4(sealedHex);
  const key = await encKey(p2, zkRoot, rid);
  const nonce = await nonceFor(p2, rid);
  if ((await macOf(p2, key, nonce, ct)) !== mac) throw new Error('Record authentication failed.');
  const ks = await keystream(p2, key, nonce);
  return unpack(ct.map((c, i) => (c - ks[i] + FIELD_MODULUS) % FIELD_MODULUS));
}

/** Reference encryption (tests only; production ciphertext comes from the proof). */
export async function encryptV4(p2, zkRoot, rid, plaintext) {
  const key = await encKey(p2, zkRoot, rid);
  const nonce = await nonceFor(p2, rid);
  const ks = await keystream(p2, key, nonce);
  const ct = plaintext.map((p, i) => (p + ks[i]) % FIELD_MODULUS);
  return { ct, mac: await macOf(p2, key, nonce, ct) };
}
