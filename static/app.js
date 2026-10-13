/* Vault client.
   Everything security-relevant and every number on screen is computed here,
   on the device. The server is a blob store: it never sees a passphrase, a
   key, a merchant name or an amount. */

'use strict';

const $ = (id) => document.getElementById(id);
let S = null;                 // sodium, after ready
let KEYS = null;              // { publicKey, privateKey, indexKey }
let TXNS = [];                // decrypted, in memory only
let CHARTS = {};
let CSRF = '';
let PASSKEY_REQUIRED = false;
let PASSKEY_AUTHENTICATED = false;
let BOOTSTRAP_NEEDED = false;
let SIMPLEFIN_AVAILABLE = false;
let EDITING_TRANSACTION_ID = null;
let ANOMALIES = new Map();

const apiFetch = async (url, options = {}) => {
  const opts = { credentials: 'same-origin', ...options, headers: { ...(options.headers || {}) } };
  const method = (opts.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD'].includes(method)) opts.headers['X-CSRF-Token'] = CSRF;
  const response = await fetch(url, opts);
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json().catch(() => ({})) : {};
  if (!response.ok) {
    const error = new Error(data.error || (response.status === 401 ? 'Your passkey session expired.' : 'Request failed.'));
    error.status = response.status;
    throw error;
  }
  if (typeof data.csrf_token === 'string') CSRF = data.csrf_token;
  return data;
};
const api = apiFetch;

const b64ToBytes = (value) => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4)), (c) => c.charCodeAt(0));
const bytesToB64 = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const publicKeyOptions = (o) => ({ ...o, challenge: b64ToBytes(o.challenge), user: o.user ? { ...o.user, id: b64ToBytes(o.user.id) } : undefined, excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64ToBytes(c.id) })), allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64ToBytes(c.id) })) });
const credentialJSON = (c) => ({
  id: c.id, rawId: bytesToB64(c.rawId), type: c.type,
  response: c.response.attestationObject ? {
    attestationObject: bytesToB64(c.response.attestationObject), clientDataJSON: bytesToB64(c.response.clientDataJSON),
    transports: c.response.getTransports ? c.response.getTransports() : [],
  } : {
    authenticatorData: bytesToB64(c.response.authenticatorData), clientDataJSON: bytesToB64(c.response.clientDataJSON),
    signature: bytesToB64(c.response.signature), userHandle: c.response.userHandle ? bytesToB64(c.response.userHandle) : null,
  },
  clientExtensionResults: c.getClientExtensionResults(),
});

/* ---- DEMO ONLY -----------------------------------------------------------
   Fixed salts so a page reload can re-derive the same key without a signup
   flow. A real build generates random salts per user at signup and stores
   them alongside the public key. Do not ship this constant.            */
let CACHED_SALTS = null;

// Legacy localStorage keys (for vaults created before server-side salts)
const SALT_KEY_ENC = 'mm_salt_enc';
const SALT_KEY_IDX = 'mm_salt_idx';

async function getSalts() {
  // Fetch per-identity KDF salts from the server. Salts are not secret,
  // just unique per identity.
  //
  // STRICT: This function fails closed. It does NOT silently fall back to
  // localStorage on auth errors (401/403) or server errors (500/network).
  // Silent fallback would change key derivation without the user's knowledge,
  // making existing records unreadable or creating a split-brain vault.
  //
  // The ONLY fallback is for legacy vaults: if localStorage already contains
  // salts from before server-side salts existed, use those. Never generate
  // new localStorage salts here.
  if (CACHED_SALTS) return CACHED_SALTS;
  try {
    const data = await api('/api/kdf/salts');
    CACHED_SALTS = {
      enc: Uint8Array.from(data.salt_enc.match(/../g).map(h => parseInt(h, 16))),
      idx: Uint8Array.from(data.salt_idx.match(/../g).map(h => parseInt(h, 16))),
      // Server returns the stored NOT NULL column (server_default 1 for
      // rows that predate KDF versioning), so a missing value can only mean
      // a legacy vault. The default must match the DB default: 1.
      kdf_version: checkKdfVersion(data.kdf_version || 1),
    };
    return CACHED_SALTS;
  } catch (e) {
    // 404: no salts set yet. Generate them (new vault) via explicit endpoint.
    if (e.status === 404) {
      console.log('No server salts yet, generating...');
      const data = await api('/api/kdf/salts/generate', { method: 'POST' });
      CACHED_SALTS = {
        enc: Uint8Array.from(data.salt_enc.match(/../g).map(h => parseInt(h, 16))),
        idx: Uint8Array.from(data.salt_idx.match(/../g).map(h => parseInt(h, 16))),
        // POST /api/kdf/salts/generate always writes and returns 3 for a
        // brand new vault, so 3 is the only correct default here.
        kdf_version: checkKdfVersion(data.kdf_version || 3),
        isNewVault: true,
      };
      return CACHED_SALTS;
    }
    // 401/403: authentication problem. Do NOT fall back; the user must auth.
    if (e.status === 401 || e.status === 403) {
      throw new Error('Authentication required for KDF salts. Please log in.');
    }
    // Legacy vaults: only use localStorage if salts ALREADY exist there.
    // Never generate new localStorage salts (would create split-brain).
    const existingEnc = localStorage.getItem(SALT_KEY_ENC);
    const existingIdx = localStorage.getItem(SALT_KEY_IDX);
    if (existingEnc && existingIdx) {
      console.warn('Using legacy localStorage salts (vault predates server-side salts)');
      return {
        enc: Uint8Array.from(existingEnc.match(/../g).map(h => parseInt(h, 16))),
        idx: Uint8Array.from(existingIdx.match(/../g).map(h => parseInt(h, 16))),
      };
    }
    // No legacy salts, server error: fail closed
    throw new Error('Could not retrieve KDF salts: ' + (e.message || 'server error'));
  }
}

function getOrCreateSalt(storageKey) {
  let saltHex = localStorage.getItem(storageKey);
  if (!saltHex) {
    // Legacy fallback: generate random 16-byte salt.
    // New vaults should use server-side salts via /api/kdf/salts.
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem(storageKey, saltHex);
  }
  return Uint8Array.from(saltHex.match(/../g).map(h => parseInt(h, 16)));
}

/* ---------- categorization: on the device, never on the server ---------- */

const RULES = [
  [/payroll|deposit/i,                                  'Income'],
  [/rent|stuyvesant/i,                                  'Housing'],
  [/trader joe|whole foods/i,                           'Groceries'],
  [/blue bottle|sweetgreen|lucali/i,                    'Dining'],
  [/mta|omny|uber|citi bike|enterprise|delta air/i,     'Transport'],
  [/con edison|verizon/i,                               'Utilities'],
  [/spotify|netflix|fans only/i,                        'Subscriptions'],
  [/amazon|apple store|rough trade|paragon|warby/i,     'Shopping'],
  [/duane reade|weill cornell|equinox|state farm/i,     'Health & insurance'],
  [/ira contribution|401\(k\)|employee deferral|employer match/i, 'Investing'],
];

const CAT_COLOR = {
  'Housing':            '#2e4b6b',
  'Groceries':          '#1f6b54',
  'Dining':             '#9e3b3b',
  'Transport':          '#7a5c2e',
  'Utilities':          '#4a6572',
  'Subscriptions':      '#6b4a7a',
  'Shopping':           '#a66a2e',
  'Health & insurance': '#3a7a7a',
  'Investing':          '#8a5b31',
  'Income':             '#1f6b54',
  'Salary':             '#1f6b54',
  'Freelance':          '#2e7b66',
  'Investment income':  '#557c3e',
  'Refund':             '#437c91',
  'Gift':               '#7a567e',
  'Other':              '#74879a',
  'Uncategorized':      '#74879a',
};

const categorize = (merchant) => {
  for (const [re, cat] of RULES) if (re.test(merchant)) return cat;
  return 'Uncategorized';
};

/* ---------- manual transaction entry ------------------------------------
   The server (app.py's put_records) only ever sees ciphertext -- it can
   check that a record LOOKS like a sealed box (hex, length bounds) but
   has no way to validate a transaction's business content, because it never
   has the key to read it. That makes these validators the sole trust
   boundary for manual-entry content, not merely UX convenience: anything
   that reaches seal()/blindIndex() below is exactly what will be stored,
   with no server-side layer able to catch a mistake here. See app.py's
   put_records() for what the server *can* still enforce (record shape,
   batch size, per-vault quota) -- that stays unchanged and still applies
   to manual records exactly like every other record. */

const MANUAL_TRANSACTION_TYPES = new Set(['expense', 'income']);
const MANUAL_CATEGORY_OPTIONS = Object.freeze({
  expense: Object.freeze([
    'Housing', 'Groceries', 'Dining', 'Transport', 'Utilities', 'Subscriptions',
    'Shopping', 'Health & insurance', 'Investing', 'Other',
  ]),
  income: Object.freeze([
    'Salary', 'Freelance', 'Investment income', 'Refund', 'Gift', 'Other',
  ]),
});
const MANUAL_CATEGORIES = new Set(Object.values(MANUAL_CATEGORY_OPTIONS).flat());
const MANUAL_AMOUNT_MAX = 999999999.99;
const MANUAL_AMOUNT_PATTERN = /^\d{1,9}(?:\.\d{1,2})?$/;

function validateTransactionName(raw) {
  if (typeof raw !== 'string') throw new Error('Transaction name is required.');
  const trimmed = raw.normalize('NFC').trim();
  if (!trimmed) throw new Error('Transaction name is required.');
  for (const ch of trimmed) {
    const point = ch.codePointAt(0);
    if (point < 0x20 || point === 0x7f) throw new Error('Transaction name contains an invalid character.');
  }
  if ([...trimmed].length > 120) throw new Error('Transaction name must be 120 characters or fewer.');
  return trimmed;
}

// Deliberately a strict allowlist pattern, not a blacklist: it defines what
// a valid amount string looks like (ASCII digits, one optional '.', 1-2
// fraction digits) rather than trying to reject "$", ",", "e", "Infinity",
// "NaN", hex, etc. one at a time. Never routes through parseFloat/Number
// before this check, so binary-float parsing of hostile input never happens.
function validateTransactionAmount(raw) {
  if (typeof raw !== 'string') throw new Error('Amount is required.');
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Amount is required.');
  if (!MANUAL_AMOUNT_PATTERN.test(trimmed)) {
    throw new Error('Enter a monetary amount such as 12.34. Maximum two decimal places.');
  }
  const value = Number(trimmed);
  if (!Number.isFinite(value) || value <= 0) throw new Error('Enter an amount greater than 0.');
  if (value > MANUAL_AMOUNT_MAX) throw new Error(`Enter an amount between 0.01 and ${MANUAL_AMOUNT_MAX.toFixed(2)}.`);
  return value;
}

function validateTransactionType(raw) {
  if (typeof raw !== 'string' || !MANUAL_TRANSACTION_TYPES.has(raw)) {
    throw new Error('Select either income or expense.');
  }
  return raw;
}

function validateTransactionCategory(raw, transactionType) {
  const type = validateTransactionType(transactionType);
  if (typeof raw !== 'string' || !MANUAL_CATEGORIES.has(raw)
      || !MANUAL_CATEGORY_OPTIONS[type].includes(raw)) {
    throw new Error(`Select a valid ${type} category.`);
  }
  return raw;
}

function selectedManualTransactionType() {
  return document.querySelector('input[name="addExpenseType"]:checked')?.value;
}

function updateManualCategoryOptions() {
  const type = validateTransactionType(selectedManualTransactionType());
  const select = $('addExpenseCategory');
  select.replaceChildren();
  for (const category of MANUAL_CATEGORY_OPTIONS[type]) {
    const option = document.createElement('option');
    option.value = category;
    option.textContent = category;
    select.append(option);
  }
  $('addExpenseCategoryHint').textContent = `Choose one ${type} category. Use Other when none of the named options fit.`;
}

function updateManualAccountOptions() {
  const select = $('addExpenseAccount');
  select.replaceChildren();
  for (const [id, rows] of accountGroups()) {
    const meta = accountMeta(id, rows);
    const option = document.createElement('option');
    option.value = id;
    option.textContent = `${meta.bank} - ${meta.type} · ${meta.label}`;
    select.append(option);
  }
  select.disabled = select.options.length === 0;
}

function validateManualAccount(raw) {
  if (typeof raw !== 'string' || !raw || !accountGroups().has(raw)) {
    throw new Error('Select a destination account.');
  }
  return raw;
}

let TRANSACTION_SUBMIT_IN_FLIGHT = false;

function openAddTransactionDialog() {
  $('addExpenseForm').reset();
  $('addExpenseError').textContent = '';
  [$('addExpenseName'), $('addExpenseAmount')].forEach((el) => el.removeAttribute('aria-invalid'));
  updateManualCategoryOptions();
  updateManualAccountOptions();
  $('addExpenseDialog').showModal();
  $('addExpenseName').focus();
}

async function submitManualTransaction(event) {
  event.preventDefault();
  if (TRANSACTION_SUBMIT_IN_FLIGHT) return;
  const error = $('addExpenseError');
  const nameField = $('addExpenseName'), amountField = $('addExpenseAmount');
  error.textContent = '';
  nameField.removeAttribute('aria-invalid');
  amountField.removeAttribute('aria-invalid');

  let name, amount, category, transactionType, account;
  try {
    transactionType = validateTransactionType(selectedManualTransactionType());
    name = validateTransactionName(nameField.value);
  } catch (e) {
    nameField.setAttribute('aria-invalid', 'true');
    error.textContent = e.message;
    return;
  }
  try {
    amount = validateTransactionAmount(amountField.value);
  } catch (e) {
    amountField.setAttribute('aria-invalid', 'true');
    error.textContent = e.message;
    return;
  }
  try {
    category = validateTransactionCategory($('addExpenseCategory').value, transactionType);
  } catch (e) {
    error.textContent = e.message;
    return;
  }
  try {
    account = validateManualAccount($('addExpenseAccount').value);
  } catch (e) {
    $('addExpenseAccount').setAttribute('aria-invalid', 'true');
    error.textContent = e.message;
    return;
  }

  TRANSACTION_SUBMIT_IN_FLIGHT = true;
  const submitButton = $('addExpenseForm').querySelector('button[type="submit"]');
  submitButton.disabled = true;
  try {
    // Explicit allowlist of user-facing fields (type, name, amount, category)
    // merged into a record built entirely from trusted, non-form values --
    // id, date, account*, and source are never taken from user input, so
    // there is no way for a submission to forge provenance (e.g. claim
    // source: "simplefin") or overwrite another record's id.
    const manual = {
      id: `manual_${crypto.randomUUID()}`,
      merchant: name,
      // This app's existing ledger convention uses positive values for
      // expenses and negative values for income.
      amount: transactionType === 'income' ? -amount : amount,
      date: new Date().toISOString().slice(0, 10),
      pending: false,
      account,
      ...accountMeta(account, accountGroups().get(account)),
      source: 'manual',
      transaction_type: transactionType,
      category,
    };
    await api('/api/records', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records: [{ blind_index: blindIndex(manual.id), sealed: seal(manual) }] }),
    });
    TXNS.push({
      ...manual,
      notes: '', tags: [], splits: [], is_transfer: false, excluded: false, fraud_status: '',
    });
    TXNS.sort((a, b) => a.date.localeCompare(b.date));
    $('statRecords').textContent = TXNS.length;
    $('addExpenseDialog').close();
    renderAccounts();
    render();
  } catch (e) {
    error.textContent = e.message || 'Could not save this transaction. Try again.';
  } finally {
    TRANSACTION_SUBMIT_IN_FLIGHT = false;
    submitButton.disabled = false;
  }
}

/* ---------- crypto ---------- */

// KDF parameters by version.
// v1: libsodium INTERACTIVE (ops=2, mem=64MB) - legacy, weaker
// v2: libsodium MODERATE (ops=3, mem=256MB) - previous default
// v3: aggressive ops (ops=5, mem=256MB) - current default for new vaults
// The version is stored server-side per identity. Existing vaults keep
// their version until the user explicitly upgrades (to avoid lockout).
//
// v3 uses 256MB (not 512MB) because iOS Safari's Jetsam killer terminates
// tabs that allocate large WASM heaps with zero warning. 256MB is the
// practical iOS ceiling; 5 ops still gives 1.67x the work per guess over v2.
// If allocation fails anyway, deriveKeys throws KDF_ALLOCATION_FAILED.
// It never falls back to another version (see deriveKeys).
function checkKdfVersion(v) {
  if (v !== 1 && v !== 2 && v !== 3) {
    throw new Error('Unsupported KDF version from server: ' + v);
  }
  return v;
}

function kdfParams(version) {
  if (version >= 3) {
    return {
      ops: 5,
      mem: 256 * 1024 * 1024,
      version: 3,
    };
  }
  if (version >= 2) {
    return {
      ops: S.crypto_pwhash_OPSLIMIT_MODERATE,
      mem: S.crypto_pwhash_MEMLIMIT_MODERATE,
      version: 2,
    };
  }
  return {
    ops: S.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    mem: S.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    version: 1,
  };
}

// Estimate passphrase entropy in bits using a conservative model.
// Counts character classes present and length. This is a lower bound;
// actual entropy may be higher for random passphrases, lower for
// dictionary words or patterns. We enforce a minimum to raise the
// cost of offline brute-force attacks.
function estimateEntropy(passphrase) {
  let classes = 0;
  if (/[a-z]/.test(passphrase)) classes += 26;
  if (/[A-Z]/.test(passphrase)) classes += 26;
  if (/[0-9]/.test(passphrase)) classes += 10;
  if (/[^a-zA-Z0-9]/.test(passphrase)) classes += 32;
  if (classes === 0) return 0;
  // Conservative: assume attacker knows the character set.
  // Deduct for common patterns (repeated chars, sequences).
  let bits = Math.log2(classes) * passphrase.length;
  if (/(.)\1{2,}/.test(passphrase)) bits -= 10;  // repeated characters
  if (/123|abc|qwe|password|admin/i.test(passphrase)) bits -= 20;  // common patterns
  return Math.max(0, bits);
}

// Minimum entropy for new vaults: 60 bits.
// At 60 bits, an attacker with 10,000 high-end GPUs (each doing ~100k
// Argon2id-MODERATE hashes/sec) would need ~1800 years on average.
// See docs/OFFLINE_ATTACK_COST.md for the full analysis.
const MIN_PASSPHRASE_ENTROPY = 60;

function checkPassphraseStrength(passphrase) {
  const entropy = estimateEntropy(passphrase);
  if (passphrase.length < 12) {
    return { ok: false, entropy, reason: "Passphrase must be at least 12 characters." };
  }
  if (entropy < MIN_PASSPHRASE_ENTROPY) {
    return {
      ok: false,
      entropy,
      reason: `Passphrase too weak (estimated ${Math.round(entropy)} bits, need ${MIN_PASSPHRASE_ENTROPY}). Use a longer passphrase with mixed character types, or a multi-word diceware phrase.`,
    };
  }
  return { ok: true, entropy };
}

async function deriveKeys(passphrase, kdfVersion) {
  const A = S.crypto_pwhash_ALG_ARGON2ID13;
  let params = kdfParams(kdfVersion || 1);

  // Per-identity salts from the server (not secret, just unique).
  // Falls back to localStorage for legacy vaults.
  const salts = await getSalts();
  const saltEnc = salts.enc;
  const saltIdx = salts.idx;

  // Derive with exactly the stored KDF version. There is NO fallback:
  // deriving a v3 vault with v2 parameters yields different keys, so
  // existing records would not decrypt and anything sealed afterwards
  // would be split across two key sets. If the device cannot allocate
  // the v3 memory, fail loudly and derive nothing.
  // See docs/CLOUD_RUN_TROUBLESHOOTING.md "KDF v3 silent fallback to v2".
  const ops = params.ops;
  const mem = params.mem;
  const usedVersion = params.version;

  const tryDerive = (o, m) => {
    const seed = S.crypto_pwhash(32, passphrase, saltEnc, o, m, A);
    const kp = S.crypto_box_seed_keypair(seed);
    const indexKey = S.crypto_pwhash(32, passphrase, saltIdx, o, m, A);
    return { seed, kp, indexKey };
  };

  let result;
  try {
    result = tryDerive(ops, mem);
  } catch (e) {
    console.error('KDF v' + usedVersion + ' derivation failed:', e && e.message);
    const err = new Error(
      'This device could not allocate the memory needed to unlock this vault ' +
      '(key derivation v' + usedVersion + ', ' + Math.round(mem / 1048576) + ' MB). ' +
      'Nothing was decrypted or saved. Try a desktop browser or close other tabs.');
    err.code = 'KDF_ALLOCATION_FAILED';
    throw err;
  }

  return {
    publicKey: result.kp.publicKey,
    privateKey: result.kp.privateKey,
    indexKey: result.indexKey,
    kdfVersion: usedVersion,
    seed: result.seed,
  };
}

/* ---------- recovery key ---------- */
// The recovery key is a 256-bit random value that encrypts the vault seed.
// It is independent of the passphrase: a strong recovery key does not
// excuse a weak passphrase, and vice versa.

async function setupRecoveryKey() {
  if (!KEYS || !KEYS.seed) throw new Error('Vault must be unlocked first');
  
  // Generate 256-bit recovery key
  const recoveryKey = S.randombytes_buf(32);
  const mnemonic = encodeRecoveryKey(recoveryKey);
  
  // Encrypt the vault seed with the recovery key
  // Use XSalsa20-Poly1305 with a random nonce
  const nonce = S.randombytes_buf(S.crypto_secretbox_NONCEBYTES);
  const encryptedSeed = S.crypto_secretbox_easy(KEYS.seed, nonce, recoveryKey);
  
  // Pack nonce + ciphertext for storage
  const blob = new Uint8Array(nonce.length + encryptedSeed.length);
  blob.set(nonce);
  blob.set(encryptedSeed, nonce.length);
  
  // Send to server (server never sees the recovery key)
  await api('/api/recovery/setup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recovery_blob: S.to_hex(blob) }),
  });
  
  // Clear the raw key from memory; return mnemonic for one-time display
  recoveryKey.fill(0);
  return mnemonic;
}

async function recoverWithKey(mnemonic, newPassphrase) {
  // Decode the mnemonic
  const recoveryKey = decodeRecoveryKey(mnemonic);
  
  try {
    // Fetch the encrypted blob (requires passkey auth)
    const data = await api('/api/recovery/blob');
    const blob = S.from_hex(data.recovery_blob);
    
    // Split nonce and ciphertext
    const nonce = blob.slice(0, S.crypto_secretbox_NONCEBYTES);
    const ciphertext = blob.slice(S.crypto_secretbox_NONCEBYTES);
    
    // Decrypt the seed
    const seed = S.crypto_secretbox_open_easy(ciphertext, nonce, recoveryKey);
    if (!seed) throw new Error('Invalid recovery key or corrupted data');
    
    // Validate new passphrase strength (don't allow weak passphrases
    // just because recovery is available)
    const strength = checkPassphraseStrength(newPassphrase);
    if (!strength.ok) {
      throw new Error('New passphrase too weak: ' + strength.reason);
    }
    
    // Generate new salts and derive keys with new passphrase
    // (This will create a new vault; the old records are re-encrypted
    //  using the recovered seed to derive the old keys)
    // For now: return the seed so the caller can complete recovery
    return seed;
  } finally {
    recoveryKey.fill(0);
  }
}

// Domain-separated backup authentication key.
// Derived from indexKey via BLAKE2b with personalization. This gives the backup
// manifest its own key without requiring additional server-side salts.
// The separation ensures a backup HMAC key compromise doesn't affect record
// encryption or blind indexing.
function backupAuthKey() {
  if (!KEYS || !KEYS.indexKey) throw new Error("Vault not unlocked");
  return S.crypto_generichash(32, S.from_string("mindful-money-backup-auth-v1"), KEYS.indexKey);
}

// Padding buckets for sealed records (in bytes, before encryption).
// All plaintexts are padded to the next bucket size to prevent length
// side-channels from revealing record contents. The buckets are sized
// to cover typical transaction records while limiting overhead.
const PAD_BUCKETS = [512, 1024, 2048, 4096, 8192];
const PAD_MAX = 8192;  // 8KB max plaintext

function padPlaintext(data) {
  if (data.length > PAD_MAX) {
    throw new Error(`Record too large: ${data.length} bytes (max ${PAD_MAX})`);
  }
  // Find the smallest bucket that fits
  let bucket = PAD_BUCKETS[PAD_BUCKETS.length - 1];
  for (const b of PAD_BUCKETS) {
    if (data.length <= b) { bucket = b; break; }
  }
  // PKCS#7-style padding: pad with bytes indicating pad length
  const padLen = bucket - data.length;
  const padded = new Uint8Array(bucket);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}

function unpadPlaintext(padded) {
  if (padded.length === 0) throw new Error('Empty padded data');
  const padLen = padded[padded.length - 1];
  if (padLen === 0 || padLen > padded.length) {
    throw new Error('Invalid padding');
  }
  // Verify all padding bytes match
  for (let i = padded.length - padLen; i < padded.length; i++) {
    if (padded[i] !== padLen) throw new Error('Invalid padding bytes');
  }
  return padded.slice(0, padded.length - padLen);
}

const seal = (obj) => {
  const plaintext = S.from_string(JSON.stringify(obj));
  const padded = padPlaintext(plaintext);
  return S.to_hex(S.crypto_box_seal(padded, KEYS.publicKey));
};

const open = (hex) => {
  const padded = S.crypto_box_seal_open(S.from_hex(hex), KEYS.publicKey, KEYS.privateKey);
  if (!padded) throw new Error('Decryption failed');
  const plaintext = unpadPlaintext(padded);
  return JSON.parse(S.to_string(plaintext));
};

const blindIndex = (id) =>
  S.to_hex(S.crypto_generichash(32, S.from_string(id), KEYS.indexKey));

// Passphrase strength estimator. Runs entirely in the browser; no passphrase
// data is stored or transmitted. This is a heuristic, not a cryptographic
// guarantee.
//
// Detects:
// - Character frequency (Shannon entropy)
// - Repeating patterns (abcabc, 123123)
// - Sequential runs (abcdef, 123456, qwerty)
// - Common passwords and dictionary words
function updatePassphraseEntropy() {
  const value = $('pass').value;  // Don't trim; spaces are valid
  const output = $('passEntropy');
  if (!value.length) {
    output.dataset.level = '';
    output.textContent = 'Shannon entropy: 0.00 bits — enter a passphrase.';
    return;
  }

  const warnings = [];
  let entropy = calcShannonEntropy(value);

  // Penalize repeating patterns
  const repeatPenalty = detectRepeatingPatterns(value);
  if (repeatPenalty > 0) {
    entropy *= (1 - repeatPenalty);
    warnings.push('repeating pattern');
  }

  // Penalize sequential runs
  const seqPenalty = detectSequentialRuns(value);
  if (seqPenalty > 0) {
    entropy *= (1 - seqPenalty);
    warnings.push('sequential characters');
  }

  // Check against common passwords
  if (isCommonPassword(value)) {
    entropy = Math.min(entropy, 10);
    warnings.push('common password');
  }

  // Character set bonus (informational, not added to entropy)
  const charsets = countCharsets(value);

  const [level, message] = entropy < 30
    ? ['weak', 'Weak' + (warnings.length ? ` (${warnings.join(', ')})` : '')]
    : entropy < 50
      ? ['decent', 'Decent' + (warnings.length ? ` (${warnings.join(', ')})` : '')]
      : entropy < 80
        ? ['good', 'Strong' + (warnings.length ? ` (${warnings.join(', ')})` : '')]
        : ['excellent', 'Excellent'];

  const charsetInfo = ` [${charsets}]`;
  output.dataset.level = level;
  output.textContent = `~${entropy.toFixed(0)} bits — ${message}${charsetInfo}`;
}

function calcShannonEntropy(s) {
  const chars = [...s];
  const counts = new Map();
  for (const c of chars) counts.set(c, (counts.get(c) || 0) + 1);
  const bitsPerChar = [...counts.values()].reduce((sum, count) => {
    const p = count / chars.length;
    return sum - p * Math.log2(p);
  }, 0);
  return bitsPerChar * chars.length;
}

function detectRepeatingPatterns(s) {
  // Check for repeated substrings of length 2-6
  const lower = s.toLowerCase();
  let maxPenalty = 0;
  for (let len = 2; len <= 6 && len <= s.length / 2; len++) {
    for (let i = 0; i <= s.length - len * 2; i++) {
      const pattern = lower.slice(i, i + len);
      let repeats = 1;
      let j = i + len;
      while (lower.slice(j, j + len) === pattern) {
        repeats++;
        j += len;
      }
      if (repeats >= 2) {
        // Penalty scales with how much of the string is repeated
        const coverage = (repeats * len) / s.length;
        maxPenalty = Math.max(maxPenalty, coverage * 0.7);
      }
    }
  }
  return Math.min(maxPenalty, 0.8);
}

function detectSequentialRuns(s) {
  const lower = s.toLowerCase();
  const sequences = [
    'abcdefghijklmnopqrstuvwxyz',
    'qwertyuiopasdfghjklzxcvbnm',
    '0123456789',
  ];
  let maxRun = 0;
  for (const seq of sequences) {
    for (let i = 0; i < lower.length - 2; i++) {
      const substr = lower.slice(i, i + 3);
      if (seq.includes(substr) || seq.split('').reverse().join('').includes(substr)) {
        let runLen = 3;
        while (i + runLen < lower.length) {
          const next = lower.slice(i, i + runLen + 1);
          const extended = next.slice(-4);
          if (seq.includes(extended) || seq.split('').reverse().join('').includes(extended)) {
            runLen++;
          } else break;
        }
        maxRun = Math.max(maxRun, runLen);
      }
    }
  }
  if (maxRun >= 3) {
    return Math.min((maxRun / s.length) * 0.6, 0.7);
  }
  return 0;
}

function isCommonPassword(s) {
  const common = [
    'password', '123456', '123456789', 'qwerty', 'abc123',
    'password1', '12345678', '111111', '123123', 'admin',
    'letmein', 'welcome', 'monkey', 'dragon', 'master',
    'passw0rd', 'p@ssword', 'p@ssw0rd',
  ];
  const lower = s.toLowerCase();
  return common.some(c => lower === c || lower.includes(c));
}

function countCharsets(s) {
  const sets = [];
  if (/[a-z]/.test(s)) sets.push('lower');
  if (/[A-Z]/.test(s)) sets.push('upper');
  if (/[0-9]/.test(s)) sets.push('digit');
  if (/[^a-zA-Z0-9]/.test(s)) sets.push('symbol');
  return sets.join('+') || 'none';
}

/* ---------- formatting ---------- */

const money = (n, sign) => {
  const s = Math.abs(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return (sign && n < 0 ? '\u2212' : '') + '$' + s;
};
const monthName = (ym) => {
  const [y, m] = ym.split('-');
  return new Date(y, m - 1, 1).toLocaleString('en-US', { month: 'short' });
};

/* ---------- flow ---------- */

async function unlock() {
  const pass = $('pass').value.trim();
  if (!pass) { $('gateNote').textContent = 'Enter a passphrase to continue.'; return; }

  $('unlockBtn').disabled = true;
  $('gateNote').textContent = 'Deriving key\u2026';
  await new Promise((r) => setTimeout(r, 30));   // let the label paint

  try {
    const saltsForKdf = await getSalts();
    const strength = checkPassphraseStrength(pass);
    // New vaults: enforce minimum entropy (block weak passphrases).
    // Existing vaults: warn only (blocking would lock out users).
    if (saltsForKdf.isNewVault && !strength.ok) {
      $('gateNote').textContent = 'Passphrase too weak: ' + strength.reason;
      $('unlockBtn').disabled = false;
      return;
    }
    if (!strength.ok) {
      console.warn('Weak passphrase detected:', strength.reason);
      $('gateNote').textContent = 'Warning: ' + strength.reason;
    }
    KEYS = await deriveKeys(pass, saltsForKdf.kdf_version || 1);
    // Clear passphrase from DOM immediately after derivation.
    // Reduces exposure window; JS cannot guarantee memory erasure but
    // removing the DOM value eliminates the most accessible copy.
    $('pass').value = '';
    updatePassphraseEntropy();
    await load(true);
    await api('/api/vault/unlocked', { method: 'POST' });
  } catch (_error) {
    KEYS = null; TXNS = [];
    $('unlockBtn').disabled = false;
    $('gateNote').textContent = (_error && _error.code === 'KDF_ALLOCATION_FAILED')
      ? _error.message
      : 'Incorrect vault passphrase or the records could not be decrypted.';
    return;
  }

  const username = $('username').value.trim();
  if (username) localStorage.setItem('vault_username', username); else localStorage.removeItem('vault_username');
  $('userGreeting').textContent = username ? `Welcome, ${username}` : '';
  $('userGreeting').hidden = !username;

  $('lock').dataset.state = 'open';
  $('lockLabel').textContent = 'Unlocked';
  $('statKey').textContent = S.to_hex(KEYS.publicKey).slice(0, 12);
  $('stats').hidden = false;
  $('syncBtn').hidden = false;
  $('connectSimplefinBtn').hidden = !SIMPLEFIN_AVAILABLE;
  $('syncSimplefinBtn').hidden = !SIMPLEFIN_AVAILABLE;
  $('addExpenseBtn').hidden = false;
  $('resetBtn').hidden = false;
  $('exportBtn').hidden = false;
  $('importBtn').hidden = false;
  $('gate').hidden = true;
  $('security').hidden = false;
  await refreshSecurity();
  $('unlockBtn').disabled = false;
}

async function load(duringUnlock = false) {
  // Fetch all records with pagination (server limits to 5000 per request)
  let allRecords = [];
  let offset = 0;
  const limit = 5000;
  while (true) {
    const data = await api(`/api/records?limit=${limit}&offset=${offset}`);
    const records = data.records || [];
    allRecords = allRecords.concat(records);
    if (records.length < limit || allRecords.length >= (data.total || 0)) break;
    offset += limit;
  }
  const records = allRecords;

  if (!records.length) { if (!duringUnlock) $('empty').hidden = false; else $('empty').hidden = false; return; }

  // Decrypt everything locally. ~20MB for a decade of history, so the whole
  // corpus lives in memory and every aggregate is computed here.
  let decrypted = records.map((r) => open(r.sealed));

  // Records written by older versions do not contain encrypted institution
  // metadata. This migration path was removed with the server-side relay.
  // Users with old records should re-import via the client-side SimpleFin
  // or demo data flow, which now generates metadata directly.
  // (Previously: fetched from /api/relay, which no longer exists.)

  TXNS = decrypted.map((t) => ({
    ...t, category: t.category || categorize(t.merchant),
    notes: typeof t.notes === 'string' ? t.notes : '',
    tags: Array.isArray(t.tags) ? t.tags : [],
    splits: Array.isArray(t.splits) ? t.splits : [],
    is_transfer: Boolean(t.is_transfer), excluded: Boolean(t.excluded),
    fraud_status: ['safe', 'fraud'].includes(t.fraud_status) ? t.fraud_status : '',
  }))
                  .sort((a, b) => a.date.localeCompare(b.date));

  $('statRecords').textContent = TXNS.length;
  renderAccounts();
  $('empty').hidden = true;
  $('dash').hidden = false;
  $('viewToggle').hidden = false;
  render();
}

async function connect(source = 'fakebank') {
  const buttons = [$('connectBtn'), $('syncBtn'), $('connectSimplefinBtn'), $('syncSimplefinBtn')];
  buttons.forEach((b) => { b.disabled = true; });
  try {
    $('connectNote').textContent = source === 'simplefin' ? 'Fetching from SimpleFin\u2026' : 'Fetching from bank\u2026';

    // Client-side only: transactions never touch the server as plaintext.
    // SimpleFin access URL is prompt-only, never stored.
    let transactions;
    if (source === 'simplefin') {
      const accessUrl = prompt('Enter your SimpleFin Access URL (from https://beta-bridge.simplefin.org):');
      if (!accessUrl) {
        $('connectNote').textContent = 'Cancelled.';
        return;
      }
      transactions = await fetchSimpleFinTransactions(accessUrl, 90);
    } else {
      // Demo data generated client-side (deterministic, same as old fakebank.py)
      transactions = generateDemoTransactions(12);
    }

    $('connectNote').textContent = `Encrypting ${transactions.length} transactions in your browser\u2026`;
    await new Promise((r) => setTimeout(r, 30));

    const prior = new Map(TXNS.map((t) => [t.id, t]));
    const editable = ['merchant', 'category', 'notes', 'tags', 'splits', 'is_transfer', 'excluded', 'fraud_status'];
    const sealedRows = transactions.map((t) => ({
      blind_index: blindIndex(t.id),
      sealed: seal(editable.reduce((merged, key) => {
        if (prior.has(t.id) && Object.hasOwn(prior.get(t.id), key)) merged[key] = prior.get(t.id)[key];
        return merged;
      }, { ...t })),
    }));

    await api('/api/records', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records: sealedRows }),
    });

    $('connectNote').textContent = '';
    await load();
  } catch (e) {
    $('connectNote').textContent = 'Error: ' + (e.message || 'Failed to connect');
    console.error('Connect failed:', e);
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
  }
}

async function handleCSVUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  // Clear the input so the same file can be re-uploaded
  event.target.value = '';

  const buttons = [$('connectBtn'), $('syncBtn'), $('connectSimplefinBtn'), $('syncSimplefinBtn')];
  buttons.forEach((b) => { if (b) b.disabled = true; });
  try {
    $('connectNote').textContent = 'Reading CSV...';
    const text = await file.text();

    // Parse client-side. Raw CSV never touches the server.
    $('connectNote').textContent = 'Parsing transactions...';
    const parseResult = parseBankCSV(text);
    const transactions = parseResult.transactions;
    const recon = parseResult.reconciliation;

    // Import preview: show reconciliation before uploading
    // Encrypted financial misinformation is still misinformation.
    let previewMsg = `CSV Import Preview:\n\n` +
      `Total rows: ${recon.total_rows}\n` +
      `Accepted: ${recon.accepted}\n` +
      `Rejected: ${recon.rejected.length}\n` +
      `Total debits: $${recon.total_debits.toFixed(2)}\n` +
      `Total credits: $${recon.total_credits.toFixed(2)}\n`;
    if (recon.rejected.length > 0) {
      previewMsg += `\nRejected rows:\n` +
        recon.rejected.slice(0, 10).map(r => `  Row ${r.row}: ${r.reason}`).join('\n');
      if (recon.rejected.length > 10)
        previewMsg += `\n  ... and ${recon.rejected.length - 10} more`;
    }
    previewMsg += `\n\nProceed with import?`;
    if (!confirm(previewMsg)) {
      $('connectNote').textContent = 'Import cancelled.';
      return;
    }

    $('connectNote').textContent = `Encrypting ${transactions.length} transactions in your browser...`;
    await new Promise((r) => setTimeout(r, 30));

    const prior = new Map(TXNS.map((t) => [t.id, t]));
    const editable = ['merchant', 'category', 'notes', 'tags', 'splits', 'is_transfer', 'excluded', 'fraud_status'];
    const sealedRows = transactions.map((t) => ({
      blind_index: blindIndex(t.id),
      sealed: seal(editable.reduce((merged, key) => {
        if (prior.has(t.id) && Object.hasOwn(prior.get(t.id), key)) merged[key] = prior.get(t.id)[key];
        return merged;
      }, { ...t })),
    }));

    // Server-side input validation happens in app.py (size limits, format checks)
    await api('/api/records', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records: sealedRows }),
    });

    $('connectNote').textContent = `Imported ${transactions.length} transactions.`;
    await load();
  } catch (e) {
    $('connectNote').textContent = 'Error: ' + (e.message || 'Failed to import CSV');
    console.error('CSV import failed:', e);
  } finally {
    buttons.forEach((b) => { if (b) b.disabled = false; });
  }
}

/* ---------- aggregates ---------- */

function monthly() {
  const m = new Map();
  for (const t of TXNS) {
    if (!reportable(t)) continue;
    const k = t.date.slice(0, 7);
    if (!m.has(k)) m.set(k, { in: 0, out: 0 });
    if (t.amount < 0) m.get(k).in -= t.amount; else m.get(k).out += t.amount;
  }
  return [...m.entries()].sort();
}

function byCategory() {
  const m = new Map();
  for (const t of TXNS) {
    if (!reportable(t) || t.amount <= 0) continue;
    const parts = t.splits.length ? t.splits : [{ category: t.category, amount: t.amount }];
    for (const part of parts) m.set(part.category, (m.get(part.category) || 0) + part.amount);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

function runningBalance() {
  let bal = 0;
  const byDay = new Map();
  for (const t of TXNS) { if (t.excluded) continue; bal -= t.amount; byDay.set(t.date, bal); }
  return [...byDay.entries()];
}

function topMerchants(n = 8) {
  const m = new Map();
  for (const t of TXNS) {
    if (!reportable(t) || t.amount <= 0) continue;
    if (!m.has(t.merchant)) m.set(t.merchant, { n: 0, sum: 0 });
    const e = m.get(t.merchant); e.n++; e.sum += t.amount;
  }
  return [...m.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, n);
}

const reportable = (t) => !t.excluded && !t.is_transfer;

/* ---------- local unusual-purchase detection -------------------------- */

const median = (values) => {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};

function robustZ(value, values) {
  if (values.length < 3) return 0;
  const center = median(values);
  const mad = median(values.map((item) => Math.abs(item - center)));
  if (mad > 1e-9) return 0.6745 * (value - center) / mad;
  const mean = values.reduce((sum, item) => sum + item, 0) / values.length;
  const deviation = Math.sqrt(values.reduce((sum, item) => sum + (item - mean) ** 2, 0) / values.length);
  return deviation > 1e-9 ? (value - mean) / deviation : 0;
}

function detectAnomalies(transactions) {
  const purchases = transactions.filter((t) => reportable(t) && t.amount > 0)
    .sort((a, b) => a.date.localeCompare(b.date) || a.id.localeCompare(b.id));
  const dayCounts = new Map();
  for (const txn of purchases) dayCounts.set(txn.date, (dayCounts.get(txn.date) || 0) + 1);
  const results = new Map();
  for (const txn of transactions.filter((item) => item.fraud_status === 'fraud')) {
    results.set(txn.id, { score: 100, level: 'Fraud', reasons: ['marked as fraud by you'], baselineSize: 0, userMarked: true });
  }

  for (let index = 0; index < purchases.length; index++) {
    const txn = purchases[index];
    if (txn.fraud_status === 'fraud') continue;
    const date = new Date(`${txn.date}T00:00:00Z`);
    const history = purchases.slice(0, index).filter((prior) => {
      const age = (date - new Date(`${prior.date}T00:00:00Z`)) / 86400000;
      return age >= 0 && age <= 180 && prior.account === txn.account && prior.fraud_status !== 'fraud';
    });
    if (txn.fraud_status === 'safe') continue;
    if (history.length < 20) continue;

    const logAmount = Math.log1p(txn.amount);
    const historyLogs = history.map((prior) => Math.log1p(prior.amount));
    const amountZ = robustZ(logAmount, historyLogs);
    const percentile = history.filter((prior) => prior.amount <= txn.amount).length / history.length;
    const merchantHistory = history.filter((prior) => prior.merchant === txn.merchant);
    const categoryHistory = history.filter((prior) => prior.category === txn.category);
    const merchantZ = merchantHistory.length >= 3
      ? robustZ(logAmount, merchantHistory.map((prior) => Math.log1p(prior.amount))) : 0;
    const categoryZ = categoryHistory.length >= 8
      ? robustZ(logAmount, categoryHistory.map((prior) => Math.log1p(prior.amount))) : 0;
    const priorDayCounts = [...new Set(history.map((prior) => prior.date))].map((day) => dayCounts.get(day));
    const velocityZ = priorDayCounts.length >= 7 ? robustZ(dayCounts.get(txn.date), priorDayCounts) : 0;

    let score = Math.max(0, Math.min(40, amountZ / 6 * 40));
    if (percentile >= 0.98) score += 15; else if (percentile >= 0.95) score += 8;
    const newMerchant = merchantHistory.length === 0;
    if (newMerchant && txn.amount > median(history.map((prior) => prior.amount))) score += 12;
    score += Math.max(0, Math.min(15, categoryZ / 6 * 15));
    score += Math.max(0, Math.min(15, merchantZ / 6 * 15));
    score += Math.max(0, Math.min(10, velocityZ / 5 * 10));
    score = Math.round(Math.min(100, score));
    if (score < 45) continue;

    const reasons = [];
    if (amountZ >= 3) reasons.push('far above your usual purchase size');
    if (percentile >= 0.98) reasons.push('in the top 2% of prior purchases');
    else if (percentile >= 0.95) reasons.push('in the top 5% of prior purchases');
    if (newMerchant) reasons.push('first purchase from this merchant');
    if (categoryZ >= 3) reasons.push(`unusually high for ${txn.category}`);
    if (merchantZ >= 3) reasons.push('different from this merchant’s normal amount');
    if (velocityZ >= 3) reasons.push('more purchases than usual that day');
    results.set(txn.id, { score, level: score >= 65 ? 'Unusual' : 'Review', reasons, baselineSize: history.length });
  }
  return results;
}

function renderFraudWatch() {
  ANOMALIES = detectAnomalies(TXNS);
  const ranked = [...ANOMALIES.entries()].map(([id, result]) => ({ txn: TXNS.find((t) => t.id === id), ...result }))
    .filter((item) => item.txn).sort((a, b) => b.score - a.score).slice(0, 6);
  $('fraudCount').textContent = String(ANOMALIES.size);
  $('fraudList').innerHTML = ranked.length ? ranked.map((item) => `<li class="fraudRow">
    <button class="fraudTransaction" data-review-anomaly="${escapeHtml(item.txn.id)}">
      <span><strong>${escapeHtml(item.txn.merchant)}</strong><small>${item.txn.date} · ${money(item.txn.amount)} · ${escapeHtml(item.reasons.join('; ') || 'combined statistical signals')}</small></span>
      <b class="riskScore ${item.level.toLowerCase()}">${item.userMarked ? 'User fraud' : `${item.level} ${item.score}`}</b>
    </button>
    <div class="fraudActions"><button class="fraudDecision safe" data-mark-safe="${escapeHtml(item.txn.id)}">Mark safe</button>${item.userMarked ? '' : `<button class="fraudDecision fraud" data-mark-fraud="${escapeHtml(item.txn.id)}">Flag fraud</button>`}</div>
  </li>`).join('') : '<li class="fraudEmpty">No purchases currently cross the review threshold.</li>';
  $('fraudList').querySelectorAll('[data-review-anomaly]').forEach((button) => button.addEventListener('click', () => openTransactionEditor(button.dataset.reviewAnomaly)));
  $('fraudList').querySelectorAll('[data-mark-safe]').forEach((button) => button.addEventListener('click', () => setFraudStatus(button.dataset.markSafe, 'safe')));
  $('fraudList').querySelectorAll('[data-mark-fraud]').forEach((button) => button.addEventListener('click', () => setFraudStatus(button.dataset.markFraud, 'fraud')));
}

async function setFraudStatus(id, status) {
  if (!['', 'safe', 'fraud'].includes(status)) return;
  const index = TXNS.findIndex((txn) => txn.id === id);
  if (index < 0) return;
  const updated = { ...TXNS[index], fraud_status: status };
  try {
    await api('/api/records', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records: [{ blind_index: blindIndex(updated.id), sealed: seal(updated) }] }),
    });
    TXNS[index] = updated;
    $('fraudActionNote').textContent = status === 'safe' ? 'Marked safe and removed from statistical review.' : 'Flagged as fraud by you.';
    render();
  } catch (error) {
    $('fraudActionNote').textContent = error.message;
  }
}

// Bank details exist only inside decrypted records. Net flows are derived
// here from encrypted amounts and are never sent to or stored by the server.
function accountGroups() {
  const groups = new Map();
  for (const txn of TXNS) {
    if (!groups.has(txn.account)) groups.set(txn.account, []);
    groups.get(txn.account).push(txn);
  }
  return groups;
}

const accountMeta = (id, rows) => {
  const txn = rows[0] || {};
  return { bank: txn.bank || id, label: txn.account_label || 'Encrypted account', type: txn.account_type || 'Account' };
};

function renderAccounts() {
  const groups = accountGroups();
  $('accounts').hidden = false;
  $('accountList').innerHTML = [...groups.entries()].map(([id, rows]) => {
    const meta = accountMeta(id, rows);
    const net = rows.filter(reportable).reduce((sum, t) => sum - t.amount, 0);
    return `<div class="accountItem">
      <div class="accountBank">${escapeHtml(meta.bank)}</div>
      <div class="accountLabel">${escapeHtml(meta.type)} · ${escapeHtml(meta.label)}<span>${rows.length} records</span></div>
      <div class="accountFlow">Net flow ${money(net, true)}</div>
    </div>`;
  }).join('');

  const totalVisible = [...groups.values()].reduce((sum, rows) => sum + rows.filter(reportable).reduce((inner, t) => inner + (t.amount < 0 ? -t.amount : 0), 0), 0);
  $('dashboardAccounts').innerHTML = [...groups.entries()].map(([id, rows]) => {
    const meta = accountMeta(id, rows);
    const contributions = rows.filter(reportable).reduce((sum, t) => sum + (t.amount < 0 ? -t.amount : 0), 0);
    const net = rows.filter(reportable).reduce((sum, t) => sum - t.amount, 0);
    const retirement = ['IRA', '401(k)'].includes(meta.type);
    const amount = retirement ? contributions : net;
    const amountLabel = retirement ? 'Contributed' : 'Net flow';
    const width = totalVisible ? Math.max(5, Math.round((contributions / totalVisible) * 100)) : 5;
    return `<article class="accountCard ${retirement ? 'retirement' : 'checking'}">
      <div class="accountCardTop"><span class="accountCardType">${escapeHtml(meta.type)}</span><span class="accountCardBadge">${rows.length} records</span></div>
      <div class="accountCardBank">${escapeHtml(meta.bank)}</div>
      <div class="accountCardLabel">${escapeHtml(meta.label)}</div>
      <div class="accountCardAmount"><small>${amountLabel}</small>${money(amount, true)}</div>
      <div class="accountCardMeta">${retirement ? 'Retirement contributions' : 'Everyday account movement'}</div>
      <progress class="accountBar" aria-label="${width}% of deposits" max="100" value="${width}"></progress>
    </article>`;
  }).join('');
}

/* ---------- private local assistant -----------------------------------
   This deliberately uses the decrypted TXNS array in this page only. It is
   a small private assistant rather than a remote LLM: no chat text,
   merchant name, amount or date is sent anywhere.                           */

const localCurrentMonth = () => new Date().toISOString().slice(0, 7);
const localMonthLabel = (ym) => new Date(ym + '-01').toLocaleString('en-US', { month: 'long', year: 'numeric' });
const localMonthRows = (ym) => TXNS.filter((t) => t.date.slice(0, 7) === ym);
const localTotals = (rows) => rows.reduce((a, t) => {
  if (!reportable(t)) return a;
  if (t.amount < 0) a.in -= t.amount; else a.out += t.amount;
  return a;
}, { in: 0, out: 0 });
const localCompleteMonths = () => monthly().filter(([k]) => k !== localCurrentMonth());
const localShare = (amount, total) => total ? Math.round((amount / total) * 100) : 0;

function localMonthReport(key, phrase) {
  const totals = localTotals(localMonthRows(key));
  const net = totals.in - totals.out;
  return `${phrase || localMonthLabel(key)}: income ${money(totals.in)}, spending ${money(totals.out)}, net ${money(net, true)}. ` +
    (net >= 0 ? 'The math behaved for once.' : 'Spending won this round.');
}

function localSummary() {
  const totals = localTotals(TXNS);
  const net = totals.in - totals.out;
  const months = monthly();
  const cats = byCategory();
  const frequent = topMerchants(1)[0];
  const latest = localCompleteMonths().slice(-1)[0] || months.slice(-1)[0];
  const accountCount = new Set(TXNS.map((t) => t.account)).size;
  const pieces = [
    `Across ${months.length} months, ${TXNS.length} transactions, and ${accountCount} accounts, income was ${money(totals.in)} and spending was ${money(totals.out)}.`,
    `Net cash flow was ${money(net, true)} — ${net >= 0 ? 'a respectable escape from the red.' : 'the red carpet has been rolled out for spending.'}`,
  ];
  if (cats.length) {
    const share = localShare(cats[0][1], totals.out);
    pieces.push(`Your largest spending category was ${cats[0][0]} at ${money(cats[0][1])} (${share}% of spending) — ${share >= 40 ? 'spectacularly over the top.' : 'the largest slice, though not exactly subtle.'}`);
  }
  if (frequent) pieces.push(`Your most frequent merchant was ${frequent[0]} with ${frequent[1].n} visits — an eccentric little recurring character.`);
  if (latest) pieces.push(localMonthReport(latest[0], `For ${localMonthLabel(latest[0])}`));
  return pieces.join(' ');
}

function localAccountReport() {
  const groups = accountGroups();
  return 'Accounts — three banks, three distinct financial personalities:\n' + [...groups.entries()].map(([id, rows]) => {
    const meta = accountMeta(id, rows);
    const net = rows.filter(reportable).reduce((sum, t) => sum - t.amount, 0);
    return `${meta.type} at ${meta.bank} — ${rows.length} records, net flow ${money(net, true)}`;
  }).join('\n');
}

let CHAT_CHART_INDEX = 0;
const CHAT_CHARTS = {};
let LAST_ATTITUDE = -1;
let CHAT_CONTEXT = { pending: '', lastTopic: '', projectionHorizon: 1 };

const CHAT_ATTITUDE = [
  'I did the arithmetic. You supplied the plot twist.',
  'The numbers are being more honest with you than you have been with them.',
  'I can explain the result; making it look innocent is outside my mandate.',
  'Consider this the receipt your optimism conveniently misplaced.',
  'No judgment. Fine, a measured amount of judgment.',
  'The spreadsheet has declined to participate in your denial.',
  'You asked for insight. Unfortunately, the transactions kept evidence.',
  'I remain on your side, though your spending has mounted a persuasive counterargument.',
];

function chatAttitude(question) {
  const q = question.toLowerCase();
  const contextual = q.includes('spend') || q.includes('expense')
    ? ['Your wallet would like to be included in future decision-making.', 'Bold spending strategy. The numbers have filed a dissent.']
    : q.includes('income') || q.includes('pay')
      ? ['Income arrived heroically; what happened afterward was less distinguished.']
      : q.includes('chart') || q.includes('graph')
        ? ['I made it visual in case the digits were too subtle.']
        : [];
  const choices = CHAT_ATTITUDE.concat(contextual);
  const random = new Uint32Array(1);
  crypto.getRandomValues(random);
  let index = random[0] % choices.length;
  if (choices.length > 1 && index === LAST_ATTITUDE) index = (index + 1) % choices.length;
  LAST_ATTITUDE = index;
  return choices[index];
}

function theilSenForecast(values, horizon) {
  if (values.length < 3) return null;
  const slopes = [];
  for (let i = 0; i < values.length; i++) {
    for (let j = i + 1; j < values.length; j++) slopes.push((values[j] - values[i]) / (j - i));
  }
  const slope = median(slopes);
  const intercept = median(values.map((value, index) => value - slope * index));
  const residuals = values.map((value, index) => Math.abs(value - (intercept + slope * index)));
  const variability = Math.max(median(residuals) * 1.4826, median(values) * 0.05);
  return Array.from({ length: horizon }, (_, step) => {
    const estimate = Math.max(0, intercept + slope * (values.length + step));
    return { estimate, low: Math.max(0, estimate - 1.28 * variability), high: estimate + 1.28 * variability };
  });
}

const futureMonthLabel = (offset) => {
  const date = new Date();
  date.setUTCDate(1); date.setUTCMonth(date.getUTCMonth() + offset);
  return date.toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
};

function localProjectionReport(horizon = 1, scope = 'cashflow') {
  const complete = localCompleteMonths();
  if (complete.length < 3) return { text: 'I need at least three complete months before making a projection. Even I have standards.', followUps: [] };
  const months = complete.slice(-12);
  if (scope === 'category') {
    const categories = byCategory().slice(0, 3).map(([name]) => name);
    const lines = categories.map((category) => {
      const values = months.map(([key]) => TXNS.filter((t) => reportable(t) && t.amount > 0 && t.date.startsWith(key)).reduce((sum, txn) => {
        if (txn.splits.length) return sum + txn.splits.filter((part) => part.category === category).reduce((partSum, part) => partSum + part.amount, 0);
        return sum + (txn.category === category ? txn.amount : 0);
      }, 0));
      const forecast = theilSenForecast(values, 1)[0];
      return `${category}: ${money(forecast.estimate)} (historical-variability range ${money(forecast.low)}–${money(forecast.high)})`;
    });
    return { text: `Next-month category projection from ${months.length} complete months:\n${lines.join('\n')}\nThis is a habit-based estimate, not a promise from the universe.`, followUps: [
      { label: 'Project cash flow', prompt: 'Project my cash flow for the next 3 months' },
      { label: 'Show category chart', prompt: 'Chart my spending by category' },
    ] };
  }
  const income = theilSenForecast(months.map(([, values]) => values.in), horizon);
  const spending = theilSenForecast(months.map(([, values]) => values.out), horizon);
  const lines = Array.from({ length: horizon }, (_, index) => {
    const net = income[index].estimate - spending[index].estimate;
    return `${futureMonthLabel(index + 1)}: income ${money(income[index].estimate)}, spending ${money(spending[index].estimate)} (${money(spending[index].low)}–${money(spending[index].high)}), net ${money(net, true)}`;
  });
  return { text: `Projection using a robust Theil–Sen trend across ${months.length} complete months:\n${lines.join('\n')}\nThe range reflects historical residual variability; it is not a guarantee or a confidence interval from a large sample.`, followUps: [
    { label: 'Project categories', prompt: 'Project my category spending next month' },
    { label: horizon === 1 ? 'Next 3 months' : 'Next month only', prompt: horizon === 1 ? 'Project my cash flow for the next 3 months' : 'Project next month' },
  ] };
}

function conversationalAnswer(question) {
  const q = question.toLowerCase().trim();
  const affirmative = /^(yes|yeah|yep|sure|please|do it)\b/.test(q);
  if (CHAT_CONTEXT.pending === 'summary_followup' && affirmative) {
    CHAT_CONTEXT.pending = 'projection_horizon';
    return { text: 'Fine. How far ahead—next month or the next three months?', noAttitude: true, followUps: [
      { label: 'Next month', prompt: 'Project next month' }, { label: 'Next 3 months', prompt: 'Project the next 3 months' },
    ] };
  }
  if (CHAT_CONTEXT.pending === 'projection_horizon' && /(next month|one month|1 month|three|3 months)/.test(q)) {
    const horizon = /(three|3 months)/.test(q) ? 3 : 1;
    CHAT_CONTEXT = { pending: 'projection_scope', lastTopic: 'projection', projectionHorizon: horizon };
    return localProjectionReport(horizon);
  }
  if (CHAT_CONTEXT.pending === 'projection_scope' && /^(category|categories|category breakdown)/.test(q)) {
    CHAT_CONTEXT.pending = '';
    return localProjectionReport(1, 'category');
  }
  if (/(project|projection|forecast|predict|next few months|future spending|what will.*spend)/.test(q)) {
    const scope = /categor/.test(q) ? 'category' : 'cashflow';
    const hasHorizon = /(next month|one month|1 month|three|3 months)/.test(q);
    if (!hasHorizon && scope === 'cashflow') {
      CHAT_CONTEXT.pending = 'projection_horizon';
      return { text: 'I can project from your completed monthly habits. Do you want next month or the next three months?', noAttitude: true, followUps: [
        { label: 'Next month', prompt: 'Project next month' }, { label: 'Next 3 months', prompt: 'Project the next 3 months' },
      ] };
    }
    const horizon = /(three|3 months)/.test(q) ? 3 : 1;
    CHAT_CONTEXT = { pending: 'projection_scope', lastTopic: 'projection', projectionHorizon: horizon };
    return localProjectionReport(horizon, scope);
  }
  const answer = localAssistantAnswer(question);
  if (q.includes('summary') || q.includes('overview') || q.includes('how am i doing')) {
    CHAT_CONTEXT = { pending: 'summary_followup', lastTopic: 'summary', projectionHorizon: 1 };
    return { text: `${typeof answer === 'string' ? answer : answer.text}\n\nWant me to project where these habits lead next?`, chart: typeof answer === 'string' ? null : answer.chart, followUps: [
      { label: 'Yes, project it', prompt: 'Yes' }, { label: 'Category trend', prompt: 'Project my category spending next month' },
    ] };
  }
  return answer;
}

function localMathReport() {
  const expenses = TXNS.filter((t) => reportable(t) && t.amount > 0).map((t) => t.amount).sort((a, b) => a - b);
  const totals = localTotals(TXNS);
  const mean = expenses.length ? totals.out / expenses.length : 0;
  const middle = Math.floor(expenses.length / 2);
  const median = expenses.length ? (expenses.length % 2 ? expenses[middle] : (expenses[middle - 1] + expenses[middle]) / 2) : 0;
  const largest = expenses.at(-1) || 0;
  const cats = byCategory();
  const top = cats[0];
  const share = top ? localShare(top[1], totals.out) : 0;
  return `Mathematical analysis: ${expenses.length} expenses totaling ${money(totals.out)}. ` +
    `Average charge ${money(mean)}; median charge ${money(median)}; largest charge ${money(largest)}. ` +
    (top ? `${top[0]} accounts for ${share}% of spending.` : 'No spending categories found.') +
    ' The arithmetic is sound; the spending choices remain under review.';
}

function localGraphicAnswer(question) {
  const q = question.toLowerCase();
  const id = `chatChart${++CHAT_CHART_INDEX}`;
  const chartBase = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 350 },
    plugins: { legend: { display: false } },
  };

  if (q.includes('category') || q.includes('where') || q.includes('goes')) {
    const data = byCategory().slice(0, 8);
    return {
      text: 'A spending-by-category chart, because apparently the budget wanted a pie chart before admitting what happened.',
      chart: {
        id,
        config: {
          type: 'doughnut',
          data: {
            labels: data.map(([name]) => name),
            datasets: [{ data: data.map(([, amount]) => amount), backgroundColor: data.map(([name]) => CAT_COLOR[name] || '#74879a'), borderWidth: 2, borderColor: '#fff' }],
          },
          options: { ...chartBase, cutout: '56%', plugins: { legend: { display: true, position: 'right', labels: { color: TICK, font: { size: 11 }, boxWidth: 10 } }, tooltip: { callbacks: { label: (c) => ` ${c.label}: ${money(c.raw)}` } } } },
        },
      },
    };
  }

  if (q.includes('account') || q.includes('bank') || q.includes('ira') || q.includes('401') || q.includes('retirement') || q.includes('contribution')) {
    const data = [...accountGroups().entries()].map(([id, rows]) => {
      const meta = accountMeta(id, rows);
      const reportRows = rows.filter(reportable);
      const total = meta.type === 'Checking'
        ? reportRows.reduce((sum, t) => sum - t.amount, 0)
        : reportRows.reduce((sum, t) => sum + (t.amount < 0 ? -t.amount : 0), 0);
      return { label: `${meta.type} · ${meta.bank}`, total };
    });
    return {
      text: 'Account flows, rendered locally. Retirement gets the contribution spotlight; checking gets the net-flow reality check.',
      chart: {
        id,
        config: {
          type: 'bar',
          data: { labels: data.map((item) => item.label), datasets: [{ data: data.map((item) => item.total), backgroundColor: ['#2e6c91', '#8a5b31', '#8a5b31'], borderRadius: 4 }] },
          options: {
            ...chartBase,
            indexAxis: 'y',
            scales: {
              x: axis({ ticks: { color: TICK, callback: (v) => '$' + (v / 1000).toFixed(1) + 'k' } }),
              y: axis({ grid: { display: false } }),
            },
            plugins: { tooltip: { callbacks: { label: (c) => ` ${money(c.raw)}` } } },
          },
        },
      },
    };
  }

  const rows = monthly();
  const spendingOnly = q.includes('spending') && !q.includes('income') && !q.includes('cash flow');
  const incomeOnly = q.includes('income') && !q.includes('spending');
  const datasets = [];
  if (!spendingOnly) datasets.push({ label: 'Income', data: rows.map(([, values]) => values.in), backgroundColor: '#18784e', borderRadius: 3 });
  if (!incomeOnly) datasets.push({ label: 'Spending', data: rows.map(([, values]) => values.out), backgroundColor: '#ae3c42', borderRadius: 3 });
  return {
    text: 'Monthly cash flow, rendered locally. The bars are factual; the financial decisions remain gloriously eccentric.',
    chart: {
      id,
      config: {
        type: 'bar',
        data: { labels: rows.map(([key]) => monthName(key)), datasets },
        options: {
          ...chartBase,
          plugins: { legend: { display: datasets.length > 1, position: 'bottom', labels: { color: TICK, font: { size: 11 }, boxWidth: 10 } }, tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}: ${money(c.raw)}` } } },
          scales: { x: axis({ grid: { display: false } }), y: axis({ ticks: { callback: (v) => '$' + (v / 1000).toFixed(1) + 'k' } }) },
        },
      },
    },
  };
}

function localAssistantAnswer(question) {
  const q = question.toLowerCase().trim();
  if (!TXNS.length) return 'Your vault has no decrypted transactions yet. Connect the demo bank first.';
  if (/^(hi|hello|hey|thanks|thank you)\b/.test(q)) {
    return 'Hello. I can summarize spending, income, categories, merchants, monthly patterns, and net cash flow. I bring arithmetic, opinions, and absolutely no chill. Everything stays in this browser.';
  }
  if (q.includes('help') || q.includes('what can')) {
    return 'Try “give me a summary,” “where did most of my money go?”, “project my cash flow,” “how much did I spend last month?”, or “who are my most frequent merchants?” I have numbers, not clairvoyance.';
  }
  if (/(chart|graph|plot|visuali[sz]|trend|doughnut|bar graph)/.test(q)) {
    return localGraphicAnswer(question);
  }
  if (q.includes('math') || q.includes('average') || q.includes('mean') || q.includes('median') || q.includes('calculate') || q.includes('percentage')) {
    return localMathReport();
  }
  if (q.includes('account') || q.includes('bank') || q.includes('ira') || q.includes('401')) {
    return localAccountReport();
  }
  if (q.includes('summary') || q.includes('summarize') || q.includes('overview') || q.includes('how am i doing')) {
    return localSummary();
  }
  if (q.includes('top') || q.includes('frequent') || q.includes('merchant')) {
    const tops = topMerchants(5);
    return 'Most frequent merchants — an eccentric little cast of characters:\n' + tops.map(([name, v], i) => `${i + 1}. ${name} — ${v.n} visits, ${money(v.sum)} total`).join('\n');
  }

  const merchantNames = [...new Set(TXNS.map((t) => t.merchant))].sort((a, b) => b.length - a.length);
  const merchant = merchantNames.find((name) => q.includes(name.toLowerCase()));
  if (merchant) {
    let rows = TXNS.filter((t) => reportable(t) && t.merchant === merchant && t.amount > 0);
    let period = 'all available data';
    if (q.includes('last month')) {
      const complete = localCompleteMonths();
      if (complete.length) { rows = rows.filter((t) => t.date.startsWith(complete.at(-1)[0])); period = localMonthLabel(complete.at(-1)[0]); }
    } else if (q.includes('this month')) {
      rows = rows.filter((t) => t.date.startsWith(localCurrentMonth()));
      period = localMonthLabel(localCurrentMonth());
    }
    return `${merchant}: ${money(rows.reduce((sum, t) => sum + t.amount, 0))} across ${rows.length} charge${rows.length === 1 ? '' : 's'} in ${period}. A factual report, not an intervention.`;
  }

  const category = Object.keys(CAT_COLOR).find((name) => q.includes(name.toLowerCase()));
  if (category && q.includes('spend')) {
    const rows = TXNS.filter((t) => reportable(t) && t.category === category && t.amount > 0);
    const amount = rows.reduce((sum, t) => sum + t.amount, 0);
    const share = localShare(amount, localTotals(TXNS).out);
    return `${category}: ${money(amount)} across ${rows.length} transaction${rows.length === 1 ? '' : 's'} (${share}% of spending). ${share >= 40 ? 'That is objectively over the top.' : 'Not a scandal, merely the largest available slice.'}`;
  }
  if (q.includes('category') || q.includes('where') || q.includes('goes') || q.includes('went')) {
    const cats = byCategory().slice(0, 5);
    return 'Spending by category — the fiscal personality test:\n' + cats.map(([name, amount], i) => `${i + 1}. ${name} — ${money(amount)}`).join('\n');
  }
  if (q.includes('last month')) {
    const complete = localCompleteMonths();
    return complete.length ? localMonthReport(complete.at(-1)[0], `Last month (${localMonthLabel(complete.at(-1)[0])})`) : 'There is no complete month in the available data yet.';
  }
  if (q.includes('this month')) return localMonthReport(localCurrentMonth(), `This month (${localMonthLabel(localCurrentMonth())})`);
  if (q.includes('month') || q.includes('monthly')) {
    return monthly().map(([key, values]) => `${localMonthLabel(key)} — income ${money(values.in)}, spending ${money(values.out)}, net ${money(values.in - values.out, true)}`).join('\n');
  }
  if (q.includes('income') || q.includes('earned') || q.includes('pay')) {
    const income = localTotals(TXNS).in;
    return `Income across the available data was ${money(income)} from ${TXNS.filter((t) => reportable(t) && t.amount < 0).length} income transactions. Good: money arrived. The eccentric part is how quickly it found somewhere else to be.`;
  }
  if (q.includes('balance') || q.includes('net cash') || q.includes('cash flow')) {
    const totals = localTotals(TXNS);
    const net = totals.in - totals.out;
    return `Net cash flow across the available data was ${money(net, true)}: ${money(totals.in)} in and ${money(totals.out)} out. ${net >= 0 ? 'Miraculously, the inflow won.' : 'Spending remains undefeated.'}`;
  }
  if (q.includes('largest') || q.includes('biggest') || q.includes('expensive')) {
    const largest = TXNS.filter((t) => reportable(t) && t.amount > 0).sort((a, b) => b.amount - a.amount)[0];
    return largest ? `The largest single expense was ${money(largest.amount)} at ${largest.merchant} on ${largest.date}. Over the top? Possibly. Confirmed by the arithmetic? Absolutely.` : 'There are no expenses in the available data.';
  }
  if (q.includes('recent')) {
    return 'Recent activity — the latest evidence:\n' + TXNS.filter(reportable).slice(-5).reverse().map((t) => `${t.date} — ${t.merchant}, ${t.amount < 0 ? 'income ' + money(-t.amount) : 'spent ' + money(t.amount)}`).join('\n');
  }
  return 'I can answer questions about your summary, spending, income, categories, merchants, monthly patterns, largest expenses, and net cash flow. Try asking for a summary. I promise to be accurate and only mildly judgmental.';
}

function appendChatMessage(role, text) {
  const bubble = document.createElement('div');
  bubble.className = `chatBubble ${role}`;
  bubble.textContent = text;
  const chart = arguments[2];
  const followUps = arguments[3] || [];
  if (chart) {
    bubble.classList.add('hasChart');
    const graph = document.createElement('div');
    graph.className = 'chatGraph';
    const canvas = document.createElement('canvas');
    canvas.id = chart.id;
    canvas.setAttribute('aria-label', 'Locally generated financial chart');
    graph.appendChild(canvas);
    bubble.appendChild(graph);
  }
  if (followUps.length) {
    const choices = document.createElement('div');
    choices.className = 'chatFollowUps';
    for (const followUp of followUps) {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = followUp.label;
      button.addEventListener('click', () => { $('chatInput').value = followUp.prompt; askChat(); });
      choices.appendChild(button);
    }
    bubble.appendChild(choices);
  }
  $('chatMessages').appendChild(bubble);
  if (chart) CHAT_CHARTS[chart.id] = new Chart($(chart.id), chart.config);
  $('chatMessages').scrollTop = $('chatMessages').scrollHeight;
}

function askChat() {
  const input = $('chatInput');
  const question = input.value.trim();
  if (!question) return;
  appendChatMessage('user', question);
  input.value = '';
  const answer = conversationalAnswer(question);
  const text = typeof answer === 'string' ? answer : answer.text;
  const attitude = typeof answer === 'string' || !answer.noAttitude ? `\n\n${chatAttitude(question)}` : '';
  appendChatMessage('bot', `${text}${attitude}`, typeof answer === 'string' ? null : answer.chart, typeof answer === 'string' ? [] : answer.followUps);
  input.focus();
}

function initChat() {
  $('chatSend').addEventListener('click', askChat);
  $('chatInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') askChat(); });
  document.querySelectorAll('[data-prompt]').forEach((button) => {
    button.addEventListener('click', () => {
      $('chatInput').value = button.dataset.prompt;
      askChat();
    });
  });
}

/* ---------- encrypted transaction editor ------------------------------ */

function openTransactionEditor(id) {
  const txn = TXNS.find((t) => t.id === id);
  if (!txn) return;
  EDITING_TRANSACTION_ID = id;
  $('editMerchant').value = txn.merchant;
  $('editCategory').value = txn.category;
  $('editNotes').value = txn.notes;
  $('editTags').value = txn.tags.join(', ');
  $('editTransfer').checked = txn.is_transfer;
  $('editExcluded').checked = txn.excluded;
  $('editFraudStatus').value = txn.fraud_status;
  $('editSplits').value = txn.splits.map((part) => `${part.category}: ${part.amount.toFixed(2)}`).join('\n');
  $('editSplitHint').textContent = txn.amount > 0
    ? `Optional. One “Category: amount” per line; entries must total ${money(txn.amount)}.`
    : 'Splits are available for spending transactions only.';
  $('editSplits').disabled = txn.amount <= 0;
  $('editError').textContent = '';
  $('transactionEditor').showModal();
}

function parseSplits(value, amount) {
  if (!value.trim()) return [];
  if (amount <= 0) throw new Error('Income transactions cannot be split.');
  const splits = value.split('\n').filter((line) => line.trim()).map((line) => {
    const match = line.match(/^(.{1,50}):\s*(\d+(?:\.\d{1,2})?)$/);
    if (!match) throw new Error(`Invalid split: “${line.trim()}”. Use Category: amount.`);
    return { category: match[1].trim(), amount: Number(match[2]) };
  });
  const total = splits.reduce((sum, part) => sum + part.amount, 0);
  if (splits.some((part) => part.amount <= 0) || Math.abs(total - amount) > 0.005) {
    throw new Error(`Split amounts must be positive and total ${money(amount)}.`);
  }
  return splits;
}

async function saveTransactionEdit(event) {
  event.preventDefault();
  const txn = TXNS.find((t) => t.id === EDITING_TRANSACTION_ID);
  if (!txn) return;
  const error = $('editError');
  try {
    const merchant = $('editMerchant').value.trim();
    if (!merchant || merchant.length > 120) throw new Error('Merchant must be between 1 and 120 characters.');
    const notes = $('editNotes').value.trim();
    if (notes.length > 1000) throw new Error('Notes cannot exceed 1,000 characters.');
    const tags = [...new Set($('editTags').value.split(',').map((tag) => tag.trim()).filter(Boolean))];
    if (tags.length > 10 || tags.some((tag) => tag.length > 40)) throw new Error('Use at most 10 tags, each 40 characters or fewer.');
    const updated = {
      ...txn, merchant, category: $('editCategory').value, notes, tags,
      splits: parseSplits($('editSplits').value, txn.amount),
      is_transfer: $('editTransfer').checked, excluded: $('editExcluded').checked,
      fraud_status: $('editFraudStatus').value,
    };
    await api('/api/records', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records: [{ blind_index: blindIndex(updated.id), sealed: seal(updated) }] }),
    });
    TXNS[TXNS.findIndex((t) => t.id === updated.id)] = updated;
    $('transactionEditor').close();
    renderAccounts();
    render();
  } catch (failure) {
    error.textContent = failure.message;
  }
}

/* ---------- charts ---------- */

const GRID = '#e2e9ed', TICK = '#74879a';
const baseOpts = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  animation: { duration: 380 },
};
const axis = (extra = {}) => ({
  grid: { color: GRID, drawTicks: false },
  border: { display: false },
  ticks: { color: TICK, font: { size: 11 }, padding: 8 },
  ...extra,
});

function draw(id, cfg) {
  CHARTS[id]?.destroy();
  CHARTS[id] = new Chart($(id), cfg);
}

function render() {
  const months = monthly();
  const cats = byCategory();
  const bal = runningBalance();
  const tops = topMerchants();

  // Headline uses the last COMPLETE month. The current month is partial by
  // definition -- on the 2nd it has rent but no paycheck, which would render
  // as an alarming loss in the largest number on the page.
  const currentKey = new Date().toISOString().slice(0, 7);
  const complete = months.filter(([k]) => k !== currentKey);
  const [lastKey, last] = (complete.length ? complete : months).slice(-1)[0];
  const net = last.in - last.out;
  $('periodLabel').textContent =
    new Date(lastKey + '-01').toLocaleString('en-US', { month: 'long', year: 'numeric' });
  $('figureNet').textContent = money(net, true);
  $('figureNet').className = 'figure ' + (net < 0 ? 'debit' : 'credit');
  $('figureSub').textContent = net < 0
    ? 'Spending outpaced income this month.'
    : 'Income covered spending this month.';
  $('figureIn').textContent = money(last.in);
  $('figureOut').textContent = money(last.out);

  draw('chMonthly', {
    type: 'bar',
    data: {
      labels: months.map(([k]) => monthName(k)),
      datasets: [
        { label: 'In',  data: months.map(([, v]) => v.in),  backgroundColor: '#1f6b54', borderRadius: 2 },
        { label: 'Out', data: months.map(([, v]) => v.out), backgroundColor: '#9e3b3b', borderRadius: 2 },
      ],
    },
    options: {
      ...baseOpts,
      plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 10, boxHeight: 10, color: TICK, font: { size: 11 } } } },
      scales: { x: axis({ grid: { display: false } }), y: axis({ ticks: { color: TICK, font: { size: 11 }, padding: 8, callback: (v) => '$' + (v / 1000) + 'k' } }) },
    },
  });

  draw('chCategory', {
    type: 'doughnut',
    data: {
      labels: cats.map(([c]) => c),
      datasets: [{
        data: cats.map(([, v]) => v),
        backgroundColor: cats.map(([c]) => CAT_COLOR[c] || '#74879a'),
        borderWidth: 2, borderColor: '#fff',
      }],
    },
    options: {
      ...baseOpts,
      cutout: '58%',
      plugins: {
        legend: { display: true, position: 'right', labels: { boxWidth: 9, boxHeight: 9, color: TICK, font: { size: 11 }, padding: 9 } },
        tooltip: { callbacks: { label: (c) => ` ${c.label}  ${money(c.raw)}` } },
      },
    },
  });

  draw('chBalance', {
    type: 'line',
    data: {
      labels: bal.map(([d]) => d),
      datasets: [{
        data: bal.map(([, v]) => v),
        borderColor: '#2e4b6b', borderWidth: 1.5,
        backgroundColor: 'rgba(46,75,107,.08)', fill: true,
        pointRadius: 0, tension: .25,
      }],
    },
    options: {
      ...baseOpts,
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ' ' + money(c.raw, true) } } },
      scales: {
        x: axis({ grid: { display: false }, ticks: { color: TICK, font: { size: 11 }, maxTicksLimit: 6, callback(v) { return monthName(this.getLabelForValue(v).slice(0, 7)); } } }),
        y: axis({ ticks: { color: TICK, font: { size: 11 }, padding: 8, callback: (v) => '$' + (v / 1000).toFixed(0) + 'k' } }),
      },
    },
  });

  draw('chMerchants', {
    type: 'bar',
    data: {
      labels: tops.map(([m]) => m),
      datasets: [{
        data: tops.map(([, v]) => v.n),
        backgroundColor: '#3d5162', borderRadius: 2, barThickness: 16,
      }],
    },
    options: {
      ...baseOpts,
      indexAxis: 'y',
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${c.raw} visits \u00b7 ${money(tops[c.dataIndex][1].sum)} total` } } },
      scales: { x: axis({ ticks: { color: TICK, font: { size: 11 }, precision: 0 } }), y: axis({ grid: { display: false }, ticks: { color: '#3d5162', font: { size: 12 } } }) },
    },
  });

  renderFraudWatch();

  $('ledgerBody').innerHTML = TXNS.slice(-14).reverse().map((t) => {
    const anomaly = ANOMALIES.get(t.id);
    const reviewState = t.fraud_status === 'fraud' ? 'Flagged fraud by you' : t.fraud_status === 'safe' ? 'Marked safe' : anomaly ? `${anomaly.level} ${anomaly.score}` : '';
    const state = [reviewState, t.is_transfer ? 'Transfer' : '', t.excluded ? 'Excluded' : '', t.splits.length ? `${t.splits.length} splits` : '', t.tags.length ? t.tags.join(', ') : ''].filter(Boolean).join(' · ');
    const category = t.splits.length ? `Split (${t.splits.length})` : t.category;
    return `
    <tr class="${t.excluded ? 'excludedRow' : ''}">
      <td class="date">${t.date}</td>
      <td title="${escapeHtml(t.notes)}">${escapeHtml(t.merchant)}${state ? `<span class="transactionState">${escapeHtml(state)}</span>` : ''}</td>
      <td><span class="tag cat-${category.toLowerCase().replace(/[^a-z]+/g, '-')}">${escapeHtml(category)}</span></td>
      <td class="num ${t.amount < 0 ? 'credit' : ''}">${t.amount < 0 ? money(-t.amount) : '\u2212' + money(t.amount)}</td>
      <td><button class="editTransaction" data-edit-transaction="${escapeHtml(t.id)}">Edit</button></td>
    </tr>`;
  }).join('');
  $('ledgerBody').querySelectorAll('[data-edit-transaction]').forEach((button) => {
    button.addEventListener('click', () => openTransactionEditor(button.dataset.editTransaction));
  });
}

/* ---------- server view ---------- */

async function renderServerView() {
  const d = await api('/api/server-view');

  $('svFigure').textContent = `${d.record_count} rows \u00d7 ${d.columns.length} columns`;
  $('statReadable').textContent = '0';

  draw('chSizes', {
    type: 'bar',
    data: {
      labels: d.size_histogram.map((s) => s.bytes + 'B'),
      datasets: [{ data: d.size_histogram.map((s) => s.n), backgroundColor: '#2b6c9b', borderRadius: 2 }],
    },
    options: { ...baseOpts, scales: { x: axis({ grid: { display: false } }), y: axis() } },
  });

  draw('chDays', {
    type: 'bar',
    data: {
      labels: d.write_days.map((w) => w.d.slice(5, 10)),
      datasets: [{ data: d.write_days.map((w) => w.n), backgroundColor: '#4a6572', borderRadius: 2 }],
    },
    options: { ...baseOpts, scales: { x: axis({ grid: { display: false } }), y: axis() } },
  });

  $('rawBody').innerHTML = d.sample.map((r) => `
    <tr><td>${r.blind_index.slice(0, 24)}\u2026</td><td>${r.sealed.slice(0, 96)}\u2026</td></tr>
  `).join('');
}

function toggleView() {
  const on = !document.body.classList.contains('sv');
  document.body.classList.toggle('sv', on);
  $('dash').hidden = on;
  $('serverview').hidden = !on;
  if (on) renderServerView();
  window.scrollTo({ top: 0, behavior: 'instant' });
}

async function reset() {
  if (!confirm('Clear every encrypted transaction from this vault? This cannot be undone.')) return;
  try {
    await deleteAllRecordsWithStepUp($('securityNote'));
    location.reload();
  } catch (error) {
    alert(webauthnMessage(error));
  }
}

/* ---------- encrypted backup export/import ---------- */

async function exportBackup() {
  if (!KEYS) {
    alert('Unlock the vault first.');
    return;
  }
  try {
    // Fetch all encrypted records from server (paginated)
    let records = [];
    let offset = 0;
    const limit = 5000;
    while (true) {
      const data = await api(`/api/records?limit=${limit}&offset=${offset}`);
      const batch = data.records || [];
      records = records.concat(batch);
      if (batch.length < limit || records.length >= (data.total || 0)) break;
      offset += limit;
    }

    // Fetch KDF salts for disaster recovery
    const salts = await api('/api/kdf/salts');

    // Create canary: sealed box proving we can decrypt
    const canaryObj = { _backup_canary: true, exported_at: new Date().toISOString() };
    const canary = seal(canaryObj);

    // Build backup file
    const backup = {
      format: 'mindful-money-backup',
      version: 1,
      exported_at: new Date().toISOString(),
      record_count: records.length,
      kdf: {
        salt_enc: salts.salt_enc,
        salt_idx: salts.salt_idx,
        kdf_version: salts.kdf_version || 1,
      },
      canary: canary,
      records: records.map(r => ({
        blind_index: r.blind_index,
        sealed: r.sealed,
        ...(r.commitment ? { commitment: r.commitment, circuit_version: r.circuit_version } : {}),
      })),
    };

    // Compute keyed integrity (HMAC-SHA256) over canonical records + metadata.
    // Uses the encryption key, so an attacker who can modify the backup file
    // but doesn't know the passphrase cannot forge a valid integrity value.
    // This detects record omission, substitution, and reordering.
    const canonical = JSON.stringify({
      records: backup.records,
      kdf: backup.kdf,
      record_count: backup.record_count,
    });
    const hmacKey = backupAuthKey();
    const hmac = S.crypto_auth_hmacsha256(S.from_string(canonical), hmacKey);
    backup.integrity = S.to_hex(hmac);
    backup.integrity_alg = "hmac-sha256";

    // Download
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const timestamp = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, '');
    a.href = url;
    a.download = `mindful-money-backup-${timestamp}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('Backup failed: ' + e.message);
    console.error('Backup export failed:', e);
  }
}

async function importBackup(event) {
  const file = event.target.files[0];
  if (!file) return;
  event.target.value = '';

  if (!KEYS) {
    alert('Unlock the vault first.');
    return;
  }

  try {
    const text = await file.text();
    const backup = JSON.parse(text);

    // Validate format
    if (backup.format !== 'mindful-money-backup') throw new Error('Not a Mindful Money backup file');
    if (backup.version !== 1) throw new Error('Unsupported backup version: ' + backup.version);
    if (backup.record_count !== backup.records.length) throw new Error('Record count mismatch (file may be truncated)');
    if (!backup.kdf || !backup.kdf.salt_enc || !backup.kdf.salt_idx) throw new Error('Missing KDF salts');

    // TRANSACTIONAL RESTORE: validate everything with candidate keys BEFORE
    // touching server state. A malformed backup must not change vault salts.
    //
    // Step 1: Derive candidate keys from backup's salts (no server mutation)
    // The passphrase field is cleared after unlock for security, so prompt if needed.
    let pass = $('pass').value;
    if (!pass) {
      pass = prompt('Enter your vault passphrase to verify the backup:');
      if (!pass) throw new Error('Passphrase required to restore backup.');
    }
    const candidateSalts = {
      enc: Uint8Array.from(backup.kdf.salt_enc.match(/../g).map(h => parseInt(h, 16))),
      idx: Uint8Array.from(backup.kdf.salt_idx.match(/../g).map(h => parseInt(h, 16))),
    };
    // Temporarily override salt cache to derive candidate keys
    const savedSalts = CACHED_SALTS;
    CACHED_SALTS = candidateSalts;
    let candidateKeys;
    try {
      candidateKeys = await deriveKeys(pass, candidateSalts.kdf_version || 1);
    } finally {
      CACHED_SALTS = savedSalts;
    }
    const candidateBackupKey = S.crypto_generichash(32,
      S.from_string("mindful-money-backup-auth-v1"), candidateKeys.indexKey);

    // Step 2: Verify HMAC with candidate keys
    const verifyCanonical = JSON.stringify({
      records: backup.records,
      kdf: backup.kdf,
      record_count: backup.record_count,
    });
    if (backup.integrity_alg !== "hmac-sha256") {
      throw new Error('Unsupported integrity algorithm.');
    }
    const expectedHmac = S.crypto_auth_hmacsha256(
      S.from_string(verifyCanonical), candidateBackupKey);
    if (S.crypto_verify_32(S.from_hex(S.to_hex(expectedHmac)),
                            S.from_hex(backup.integrity)) !== 0) {
      throw new Error('Integrity check failed (file corrupted or tampered)');
    }

    // Step 3: Verify canary decrypts with candidate keys
    const candidateOpen = (hex) =>
      JSON.parse(S.to_string(
        S.crypto_box_seal_open(S.from_hex(hex), candidateKeys.publicKey, candidateKeys.privateKey)));
    try {
      const canaryObj = candidateOpen(backup.canary);
      if (!canaryObj._backup_canary) throw new Error('Invalid canary');
    } catch (e) {
      throw new Error('Cannot decrypt backup: wrong passphrase. ' + e.message);
    }

    // Step 4: ONLY NOW apply salts to server (backup is fully validated)
    try {
      const saltResp = await api('/api/kdf/salts');
      if (saltResp.salt_enc !== backup.kdf.salt_enc || saltResp.salt_idx !== backup.kdf.salt_idx) {
        await api('/api/kdf/salts/migrate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            salt_enc: backup.kdf.salt_enc,
            salt_idx: backup.kdf.salt_idx,
            force: true,
          }),
        });
        CACHED_SALTS = null;
        KEYS = await deriveKeys(pass, backup.kdf.kdf_version || 1);
      }
    } catch (e) {
      if (e.status === 404 || (e.message && e.message.includes('not found'))) {
        await api('/api/kdf/salts/migrate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            salt_enc: backup.kdf.salt_enc,
            salt_idx: backup.kdf.salt_idx,
          }),
        });
        CACHED_SALTS = null;
        KEYS = await deriveKeys(pass, backup.kdf.kdf_version || 1);
      } else {
        throw e;
      }
    }

    // Upload records in batches
    const batchSize = 100;
    let uploaded = 0;
    for (let i = 0; i < backup.records.length; i += batchSize) {
      const batch = backup.records.slice(i, i + batchSize).map(r => ({
        blind_index: r.blind_index,
        sealed: r.sealed,
      }));
      await api('/api/records', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ records: batch }),
      });
      uploaded += batch.length;
    }

    alert(`Restored ${uploaded} records from backup.`);
    await load();
  } catch (e) {
    alert('Restore failed: ' + e.message);
    console.error('Backup import failed:', e);
  }
}

async function resetPassphrase() {
  if (!confirm('Resetting the vault passphrase permanently erases all encrypted financial records because the old key cannot be recovered. Continue?')) return;
  const note = $('gateNote');
  $('resetPassphraseBtn').disabled = true;
  try {
    await deleteAllRecordsWithStepUp(note);
    KEYS = null; TXNS = [];
    $('pass').value = '';
    updatePassphraseEntropy();
    $('gate').querySelector('h1').textContent = 'Set a new passphrase';
    note.textContent = 'Vault data erased. Enter a new passphrase, unlock, then reconnect the demo banks.';
    $('pass').focus();
  } catch (error) {
    note.textContent = error.message;
  } finally {
    $('resetPassphraseBtn').disabled = false;
  }
}

/* ---------- optional passkeys ---------- */

function webauthnMessage(error) {
  if (!window.PublicKeyCredential) return 'This browser does not support WebAuthn passkeys.';
  if (error?.name === 'NotAllowedError') return 'The passkey ceremony was cancelled or timed out.';
  return error?.message || 'The passkey operation failed.';
}

async function authenticateWithPasskey(note) {
  if (!window.PublicKeyCredential) throw new Error('This browser does not support WebAuthn passkeys.');
  if (note) note.textContent = 'Waiting for your authenticator...';
  const options = await api('/api/passkeys/login/options', { method: 'POST' });
  const credential = await navigator.credentials.get({ publicKey: publicKeyOptions(options) });
  const result = await api('/api/passkeys/login/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ credential: credentialJSON(credential) }) });
  CSRF = result.csrf_token;
  PASSKEY_AUTHENTICATED = true;
  return result;
}

async function deleteAllRecordsWithStepUp(note) {
  try {
    return await api('/api/records', { method: 'DELETE' });
  } catch (error) {
    if (error.status === 409) {
      throw new Error('Enroll a passkey before deleting every server-side vault record.');
    }
    if (error.status !== 401) throw error;
    // This retry remains scoped to the destructive action the user already
    // confirmed. Session rotation updates CSRF but does not touch KEYS.
    await authenticateWithPasskey(note);
    return await api('/api/records', { method: 'DELETE' });
  }
}

async function registerPasskey() {
  const note = $('securityNote');
  try {
    if (!window.PublicKeyCredential) throw new Error('This browser does not support WebAuthn passkeys.');
    note.textContent = 'Waiting for your authenticator…';
    const options = await api('/api/passkeys/register/options', { method: 'POST' });
    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions(options) });
    const result = await api('/api/passkeys/register/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ credential: credentialJSON(credential), label: $('passkeyLabel').value || 'Passkey' }) });
    if (result.verified) {
      PASSKEY_REQUIRED = true;
      note.textContent = 'Passkey enrolled. Authenticate with it to begin the protected session.';
      await authenticateWithPasskey(note);
      await refreshSecurity();
      note.textContent = 'Passkey protection is enabled. Future access requires your passkey and then your passphrase.';
    }
  } catch (error) { note.textContent = webauthnMessage(error); }
}

async function loginPasskey() {
  const note = $('passkeyGateNote');
  try {
    note.textContent = 'Waiting for your authenticator…';
    await authenticateWithPasskey(note);
    $('passkeyGate').hidden = true; $('gate').hidden = false; $('gate').querySelector('h1').textContent = 'Unlock vault with passphrase';
    $('gateNote').textContent = 'Passkey accepted. Your passphrase now decrypts the vault locally.';
  } catch (error) { note.textContent = webauthnMessage(error); }
}

async function bootstrapPasskey() {
  const note = $('passkeyGateNote');
  try {
    if (!window.PublicKeyCredential) throw new Error('This browser does not support WebAuthn passkeys.');
    // Prompt for bootstrap token (prevents unauthorized enrollment)
    const token = prompt('Enter the bootstrap token (from VAULT_BOOTSTRAP_TOKEN):');
    if (!token) {
      note.textContent = 'Bootstrap cancelled.';
      return;
    }
    note.textContent = 'Creating your passkey…';
    const options = await api('/api/passkeys/bootstrap/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: token }),
    });
    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions(options) });
    const result = await api('/api/passkeys/bootstrap/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: credentialJSON(credential), label: 'Primary passkey', bootstrap_token: token }),
    });
    CSRF = result.csrf_token;
    PASSKEY_REQUIRED = true; PASSKEY_AUTHENTICATED = true; BOOTSTRAP_NEEDED = false;
    $('passkeyGate').hidden = true; $('gate').hidden = false;
    $('gate').querySelector('h1').textContent = 'Create your vault passphrase';
    $('gateNote').textContent = 'Passkey created. Now choose a passphrase to encrypt your data.';
  } catch (error) { note.textContent = webauthnMessage(error); }
}

async function refreshSecurity() {
  $('passkeyState').textContent = PASSKEY_REQUIRED ? 'Enabled' : 'Not enabled';
  $('enablePasskeyBtn').hidden = PASSKEY_REQUIRED;
  $('addPasskeyBtn').hidden = !PASSKEY_REQUIRED;
  $('disablePasskeyBtn').hidden = !PASSKEY_REQUIRED;
  $('signOutBtn').hidden = !PASSKEY_REQUIRED;
  if (!PASSKEY_REQUIRED) { $('passkeyList').innerHTML = ''; return; }
  const { passkeys } = await api('/api/passkeys');
  $('passkeyList').innerHTML = passkeys.map((p) => `<div class="passkeyItem"><span>${escapeHtml(p.label)}${p.backed_up ? ' · backed up' : ''}</span><button data-rename="${p.credential_id}">Rename</button><button data-remove="${p.credential_id}">Remove</button></div>`).join('');
  $('passkeyList').querySelectorAll('[data-rename]').forEach((button) => button.onclick = async () => { const label = prompt('New passkey label'); if (label) { await api(`/api/passkeys/${button.dataset.rename}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label }) }); await refreshSecurity(); } });
  $('passkeyList').querySelectorAll('[data-remove]').forEach((button) => button.onclick = async () => { try { await api(`/api/passkeys/${button.dataset.remove}`, { method: 'DELETE' }); await refreshSecurity(); } catch (e) { $('securityNote').textContent = e.message; } });
}

function lockVault() {
  if (KEYS) { KEYS.privateKey?.fill(0); KEYS.indexKey?.fill(0); KEYS.publicKey?.fill(0); }
  KEYS = null; TXNS = [];
  CHAT_CONTEXT = { pending: '', lastTopic: '', projectionHorizon: 1 };
  Object.values(CHARTS).forEach((c) => c.destroy()); CHARTS = {};
  Object.values(CHAT_CHARTS).forEach((c) => c.destroy());
  $('ledgerBody').textContent = ''; $('accountList').textContent = ''; $('dashboardAccounts').textContent = ''; $('chatMessages').textContent = ''; $('rawBody').textContent = '';
  ['dash','empty','serverview','security','stats','accounts','syncBtn','syncSimplefinBtn','addExpenseBtn','resetBtn','viewToggle'].forEach((id) => $(id).hidden = true);
  document.body.classList.remove('sv'); $('pass').value = ''; updatePassphraseEntropy(); $('lock').dataset.state = 'locked'; $('lockLabel').textContent = 'Locked';
  $('userGreeting').hidden = true;
  $('unlockBtn').disabled = false;
  $('gate').hidden = false; $('gate').querySelector('h1').textContent = 'Unlock vault with passphrase';
}

async function signOut() {
  lockVault();
  await api('/api/logout', { method: 'POST' });
  CSRF = ''; PASSKEY_AUTHENTICATED = false;
  const s = await api('/api/session'); CSRF = s.csrf_token;
  $('gate').hidden = true; $('passkeyGate').hidden = false;
}

async function disablePasskeys() {
  if (!confirm('Disable passkey protection and return to passphrase-only access?')) return;
  try { await api('/api/passkeys/disable', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ confirm_unlocked: true }) }); PASSKEY_REQUIRED = false; PASSKEY_AUTHENTICATED = false; await refreshSecurity(); $('securityNote').textContent = 'Passkey protection disabled. Passphrase-only access is restored.'; } catch (e) { $('securityNote').textContent = e.message; }
}

/* ---------- boot ---------- */

(async () => {
  // Attach critical UI listeners first, so the page is interactive even
  // if an API call fails. Previously a single failed fetch would abort
  // the entire boot sequence and leave the UI dead.
  try {
    $('unlockBtn').addEventListener('click', unlock);
    $('pass').addEventListener('input', updatePassphraseEntropy);
    $('pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
    $('username').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
    $('togglePass').addEventListener('click', () => {
      const input = $('pass');
      const btn = $('togglePass');
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🙈';
        btn.setAttribute('aria-label', 'Hide passphrase');
      } else {
        input.type = 'password';
        btn.textContent = '👁';
        btn.setAttribute('aria-label', 'Show passphrase');
      }
    });
  } catch (e) {
    console.error('Failed to attach UI listeners:', e);
  }

  try {
    const sessionInfo = await api('/api/session'); CSRF = sessionInfo.csrf_token;
    const status = await api('/api/passkeys/status');
    PASSKEY_REQUIRED = status.passkey_required;
    PASSKEY_AUTHENTICATED = status.authenticated;
    BOOTSTRAP_NEEDED = status.bootstrap_needed || false;
  } catch (e) {
    console.error('Failed to fetch session status:', e);
    // Continue with defaults; user can still try to unlock
  }
  SIMPLEFIN_AVAILABLE = true;
  try {
    await sodium.ready;
    S = sodium;
  } catch (e) {
    console.error('Failed to init crypto:', e);
    $('gateNote').textContent = 'Failed to load cryptography. Refresh the page.';
    return;
  }
  try {
    $('username').value = localStorage.getItem('vault_username') || '';
  $('connectBtn').addEventListener('click', () => connect('fakebank'));
  $('syncBtn').addEventListener('click', () => connect('fakebank'));
  $('connectSimplefinBtn').addEventListener('click', () => connect('simplefin'));
  $('syncSimplefinBtn').addEventListener('click', () => connect('simplefin'));
  $('csvFile').addEventListener('change', handleCSVUpload);
  $('viewToggle').addEventListener('click', toggleView);
  $('resetBtn').addEventListener('click', reset);
  $('exportBtn').addEventListener('click', exportBackup);
  $('importBtn').addEventListener('click', () => $('importFile').click());
  $('importFile').addEventListener('change', importBackup);
  $('resetPassphraseBtn').addEventListener('click', resetPassphrase);
  $('passkeyLoginBtn').addEventListener('click', loginPasskey);
  $('enablePasskeyBtn').addEventListener('click', registerPasskey);
  $('addPasskeyBtn').addEventListener('click', registerPasskey);
  $('lockVaultBtn').addEventListener('click', lockVault);
  $('signOutBtn').addEventListener('click', signOut);
  $('disablePasskeyBtn').addEventListener('click', disablePasskeys);
  $('transactionEditForm').addEventListener('submit', saveTransactionEdit);
  $('editCancel').addEventListener('click', () => $('transactionEditor').close());
  $('editCancelX').addEventListener('click', () => $('transactionEditor').close());
  $('addExpenseBtn').addEventListener('click', openAddTransactionDialog);
  $('addExpenseForm').addEventListener('submit', submitManualTransaction);
  document.querySelectorAll('input[name="addExpenseType"]').forEach((radio) => radio.addEventListener('change', updateManualCategoryOptions));
/* ---------- recovery UI handlers ---------- */

async function handleSetupRecovery() {
  const note = $('recoveryNote');
  try {
    if (!KEYS) { note.textContent = 'Unlock your vault first.'; return; }
    if (!confirm('Generate a recovery key? You will need to write down 32 words on paper.')) return;
    
    note.textContent = 'Generating recovery key...';
    const mnemonic = await setupRecoveryKey();
    
    // Display the mnemonic ONE TIME
    $('recoveryWords').textContent = mnemonic;
    $('recoveryDisplay').hidden = false;
    $('recoverForm').hidden = true;
    note.textContent = '';
    
    // Clear mnemonic from JS memory after display (user must have written it down)
    // Note: the DOM still contains it until they click Done
  } catch (e) {
    note.textContent = 'Error: ' + (e.message || 'Failed to generate recovery key');
  }
}

async function handleRecoverVault() {
  const note = $('recoverNote');
  const mnemonic = $('recoverMnemonic').value.trim();
  const newPass = $('recoverNewPass').value;
  
  if (!mnemonic || !newPass) {
    note.textContent = 'Enter both the recovery key and a new passphrase.';
    return;
  }
  
  // Validate new passphrase strength BEFORE starting (don't leave vault
  // in a half-migrated state due to a weak passphrase)
  const strength = checkPassphraseStrength(newPass);
  if (!strength.ok) {
    note.textContent = 'New passphrase too weak: ' + strength.reason;
    return;
  }
  
  if (!confirm('This will re-encrypt all your records with the new passphrase. Continue?')) {
    return;
  }
  
  try {
    note.textContent = 'Recovering seed...';
    const oldSeed = await recoverWithKey(mnemonic, newPass);
    
    // Clear sensitive inputs immediately
    $('recoverMnemonic').value = '';
    $('recoverNewPass').value = '';
    
    // Reconstruct old keys from recovered seed
    const oldKp = S.crypto_box_seed_keypair(oldSeed);
    
    // Fetch all encrypted records
    note.textContent = 'Fetching encrypted records...';
    const recordsData = await api('/api/records');
    const records = recordsData.records || [];
    
    if (records.length === 0) {
      note.textContent = 'No records to re-encrypt. Vault is empty.';
      oldSeed.fill(0);
      return;
    }
    
    // Decrypt each record with old key
    note.textContent = `Decrypting ${records.length} records...`;
    const decrypted = [];
    for (const r of records) {
      try {
        const padded = S.crypto_box_seal_open(
          S.from_hex(r.sealed), oldKp.publicKey, oldKp.privateKey
        );
        if (!padded) throw new Error('Decryption failed');
        const plaintext = unpadPlaintext(padded);
        const obj = JSON.parse(S.to_string(plaintext));
        decrypted.push({ blind_index: r.blind_index, data: obj });
      } catch (e) {
        throw new Error(`Failed to decrypt record ${r.blind_index.slice(0, 8)}...: ${e.message}`);
      }
    }
    
    // Clear old seed from memory
    oldSeed.fill(0);
    oldKp.privateKey.fill(0);
    
    // Generate new salts (this creates a new vault identity for the new passphrase)
    note.textContent = 'Generating new vault...';
    CACHED_SALTS = null;  // Force regeneration
    const newSalts = await getSalts();
    if (!newSalts.isNewVault) {
      throw new Error('Expected new salts for re-encryption, got existing');
    }
    
    // Derive new keys
    note.textContent = 'Deriving new keys (this takes a while)...';
    const newKeys = await deriveKeys(newPass, newSalts.kdf_version || 3);
    
    // Re-encrypt each record with new key (with padding)
    note.textContent = `Re-encrypting ${decrypted.length} records...`;
    const reencrypted = decrypted.map(({ blind_index, data }) => {
      // Temporarily swap KEYS for seal()
      const savedKeys = KEYS;
      KEYS = newKeys;
      try {
        return { blind_index, sealed: seal(data) };
      } finally {
        KEYS = savedKeys;
      }
    });
    
    // Upload re-encrypted records (upsert by blind_index replaces old ciphertext)
    note.textContent = `Uploading ${reencrypted.length} re-encrypted records...`;
    const BATCH = 50;
    for (let i = 0; i < reencrypted.length; i += BATCH) {
      const batch = reencrypted.slice(i, i + BATCH);
      await api('/api/records', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ records: batch }),
      });
      note.textContent = `Uploading... ${Math.min(i + BATCH, reencrypted.length)}/${reencrypted.length}`;
    }
    
    // Update KEYS to new keys and reload
    KEYS = newKeys;
    $('recoverForm').hidden = true;
    note.textContent = `Recovery complete. ${reencrypted.length} records re-encrypted with new passphrase.`;
    
    // Clear new keys from temp variable (KEYS now holds them)
    newKeys.seed?.fill(0);
    
    // Refresh the UI
    await load(true);
    
  } catch (e) {
    note.textContent = 'Recovery failed: ' + (e.message || 'Unknown error');
    console.error('Recovery failed:', e);
  }
}

async function handleDeleteRecovery() {
  if (!confirm('Delete the recovery key? You will lose the ability to recover with the existing key.')) return;
  try {
    await api('/api/recovery/delete', { method: 'POST' });
    $('recoveryNote').textContent = 'Recovery key deleted.';
    refreshRecoveryState();
  } catch (e) {
    $('recoveryNote').textContent = 'Error: ' + (e.message || 'Failed to delete');
  }
}

async function refreshRecoveryState() {
  try {
    await api('/api/recovery/blob');
    $('recoveryState').textContent = 'Set up';
    $('setupRecoveryBtn').hidden = true;
    $('deleteRecoveryBtn').hidden = false;
  } catch (e) {
    $('recoveryState').textContent = 'Not set up';
    $('setupRecoveryBtn').hidden = false;
    $('deleteRecoveryBtn').hidden = true;
  }
}

  $('addExpenseCancel').addEventListener('click', () => $('addExpenseDialog').close());
  $('addExpenseCancelX').addEventListener('click', () => $('addExpenseDialog').close());
  // Recovery key UI
  $('setupRecoveryBtn').addEventListener('click', handleSetupRecovery);
  $('recoverVaultBtn').addEventListener('click', () => {
    $('recoverForm').hidden = false;
    $('recoveryDisplay').hidden = true;
  });
  $('cancelRecoverBtn').addEventListener('click', () => {
    $('recoverForm').hidden = true;
    $('recoverMnemonic').value = '';
    $('recoverNewPass').value = '';
  });
  $('doRecoverBtn').addEventListener('click', handleRecoverVault);
  $('deleteRecoveryBtn').addEventListener('click', handleDeleteRecovery);
  $('recoveryConfirm').addEventListener('change', (e) => {
    $('recoveryDoneBtn').disabled = !e.target.checked;
  });
  $('recoveryDoneBtn').addEventListener('click', () => {
    $('recoveryDisplay').hidden = true;
    $('recoveryWords').textContent = '';
    $('recoveryConfirm').checked = false;
    $('recoveryDoneBtn').disabled = true;
    $('recoveryNote').textContent = 'Recovery key saved. Store the paper copy safely.';
    refreshRecoveryState();
  });
  initChat();
  if (BOOTSTRAP_NEEDED) {
    // First-time setup: no passkeys exist. Show bootstrap enrollment.
    $('gate').hidden = true; $('passkeyGate').hidden = false;
    $('passkeyGate').querySelector('h1').textContent = 'Set up your passkey';
    $('passkeyGateNote').textContent = 'This is a new vault. Create a passkey to secure it.';
    // Replace login button with bootstrap button
    const loginBtn = $('passkeyLoginBtn');
    if (loginBtn) {
      loginBtn.textContent = 'Create passkey';
      loginBtn.onclick = bootstrapPasskey;
    }
  }
  else if (PASSKEY_REQUIRED && !PASSKEY_AUTHENTICATED) { $('gate').hidden = true; $('passkeyGate').hidden = false; }
  else $('gateNote').textContent = 'Deriving a key takes a moment \u2014 that slowness is deliberate.';
  } catch (e) {
    console.error('Boot failed:', e);
    $('gateNote').textContent = 'Failed to initialize. Refresh the page.';
  }
})();
// Deploy trigger 20261011225949
