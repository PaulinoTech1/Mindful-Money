// PaulinoTech Mindful Money -- key-bound sealed manual transaction circuit.
// circuit_version: "manual-transaction-v4"
//
// Proves, without revealing them:
//
//   "I know a name/amount/category tuple satisfying the same validation
//    rules as v2, AND I know the vault ZK root `zk_root` whose commitment
//    Poseidon2(DS_KEY, zk_root, vault_salt) equals the public
//    `key_commitment` registered for this vault, AND the public
//    `ciphertext`/`mac` outputs are the Poseidon2 stream encryption of that
//    tuple under the per-record key derived from zk_root."
//
// Closes the v3 gap: in v3 `enc_key` was a free witness, so a prover could
// encrypt under any random key and still produce a valid proof. Here the
// per-record key and nonce are derived IN-CIRCUIT and the root is bound to
// a server-stored commitment, so a key that is not the vault's own key
// cannot satisfy the circuit.
//
// The server fills challenge, record_id_hash, schema_version,
// key_commitment and vault_salt from its own database rows; it never takes
// them from the client. See docs/ZKP_BINDING.md.
//
// Key schedule (all Poseidon2, domain separated):
//   key_commitment = H(DS_KEY, zk_root, vault_salt)
//   enc_key        = H(DS_ENC, zk_root, record_id_hash)
//   enc_nonce      = H(DS_NONCE, record_id_hash)   (asserted equal)
//   keystream[i]   = H(enc_key, enc_nonce, i)
//   ciphertext[i]  = plaintext[i] + keystream[i]
//   mac            = H(DS_MAC, enc_key, enc_nonce, ciphertext[0..7])
//
// zk_root is derived in the browser as
//   BLAKE2b-256("mm-zkp-root-v1" || vault X25519 private key)[0..31]
// (248 bits), see static/zkp/manual_expense_v4_client.js.

use poseidon::poseidon2::Poseidon2;

global MAX_NAME_BYTES: u32 = 120;
global CATEGORY_COUNT: u64 = 16;
global MAX_AMOUNT_CENTS: u64 = 99999999999;
global SCHEMA_VERSION: u64 = 4;
// "PAULINOTECH_MANUAL_TX_V4"
global DOMAIN_SEPARATOR: Field = 0x5041554c494e4f544543485f4d414e55414c5f54585f5634;
// "MM_ZKP_KEY_COMMIT_V4"
global DS_KEY: Field = 0x4d4d5f5a4b505f4b45595f434f4d4d49545f5634;
// "MM_ZKP_ENC_KEY_V4"
global DS_ENC: Field = 0x4d4d5f5a4b505f454e435f4b45595f5634;
// "MM_ZKP_NONCE_V4"
global DS_NONCE: Field = 0x4d4d5f5a4b505f4e4f4e43455f5634;
// "MM_ZKP_MAC_V4"
global DS_MAC: Field = 0x4d4d5f5a4b505f4d41435f5634;
global PREIMAGE_LEN: u32 = MAX_NAME_BYTES + 9;
global CIPHERTEXT_LEN: u32 = 8;
global BYTES_PER_FIELD: u32 = 30;

pub fn key_commitment_of(zk_root: Field, vault_salt: Field) -> Field {
    Poseidon2::hash([DS_KEY, zk_root, vault_salt], 3)
}

pub fn enc_key_of(zk_root: Field, record_id_hash: Field) -> Field {
    Poseidon2::hash([DS_ENC, zk_root, record_id_hash], 3)
}

pub fn nonce_of(record_id_hash: Field) -> Field {
    Poseidon2::hash([DS_NONCE, record_id_hash], 2)
}

fn main(
    // ---- private witness: never leaves the browser ----
    name_bytes: [u8; MAX_NAME_BYTES],
    name_length: u32,
    amount_cents: u64,
    category_id: u64,
    has_category: bool,
    commitment_blinding: Field,
    zk_root: Field,
    enc_nonce: Field,
    // ---- public inputs: filled by Flask from its own rows ----
    challenge: pub Field,
    record_id_hash: pub Field,
    schema_version: pub u64,
    key_commitment: pub Field,
    vault_salt: pub Field,
) -> pub (Field, [Field; CIPHERTEXT_LEN], Field) {
    assert(schema_version == SCHEMA_VERSION);

    // ---- key binding (the v3 fix) ----
    assert(key_commitment_of(zk_root, vault_salt) == key_commitment, "key commitment mismatch");
    let enc_key = enc_key_of(zk_root, record_id_hash);
    assert(enc_nonce == nonce_of(record_id_hash), "nonce mismatch");

    // ---- name bound ----------------------------------------------------
    // Bounds UTF-8 *bytes*, not Unicode *code points*. The browser UI's
    // "1 to 120 characters" promise (static/app.js validateTransactionName) is
    // a code-point bound; a 120-character name using multi-byte UTF-8 can
    // exceed 120 bytes. This circuit uses the stricter byte-size bound and
    // separately proves well-formed UTF-8 below; it does not attempt to
    // count Unicode code points or prove NFC normalization.
    assert(name_length >= 1);
    assert(name_length <= MAX_NAME_BYTES);
    // Validate well-formed UTF-8, reject ASCII control characters, and
    // require the same basic outer-space canonicalization as the browser.
    // The continuation bounds reject overlong encodings, UTF-16 surrogate
    // code points, and values above U+10FFFF.
    let mut continuation_bytes: u8 = 0;
    let mut next_min: u8 = 0x80;
    let mut next_max: u8 = 0xbf;
    for i in 0..MAX_NAME_BYTES {
        if i < name_length {
            let byte = name_bytes[i];
            if continuation_bytes > 0 {
                assert(byte >= next_min);
                assert(byte <= next_max);
                continuation_bytes -= 1;
                next_min = 0x80;
                next_max = 0xbf;
            } else {
                if byte < 0x80 {
                    assert(byte >= 0x20);
                    assert(byte != 0x7f);
                    if (i == 0) | (i + 1 == name_length) {
                        assert(byte != 0x20);
                    }
                } else {
                    let is_two_byte = (byte >= 0xc2) & (byte <= 0xdf);
                    let is_three_byte = (byte >= 0xe0) & (byte <= 0xef);
                    let is_four_byte = (byte >= 0xf0) & (byte <= 0xf4);
                    assert(is_two_byte | is_three_byte | is_four_byte);

                    if is_two_byte {
                        continuation_bytes = 1;
                    } else if is_three_byte {
                        continuation_bytes = 2;
                        if byte == 0xe0 {
                            next_min = 0xa0; // exclude overlong encoding
                        } else if byte == 0xed {
                            next_max = 0x9f; // exclude UTF-16 surrogates
                        }
                    } else {
                        continuation_bytes = 3;
                        if byte == 0xf0 {
                            next_min = 0x90; // exclude overlong encoding
                        } else if byte == 0xf4 {
                            next_max = 0x8f; // cap at U+10FFFF
                        }
                    }
                }
            }
        } else {
            assert(name_bytes[i] == 0);
        }
    }
    assert(continuation_bytes == 0);

    // ---- amount bound ----------------------------------------------------
    assert(amount_cents > 0);
    assert(amount_cents <= MAX_AMOUNT_CENTS);

    // ---- category membership ----------------------------------------------
    // has_category preserves the versioned circuit's optional-category
    // representation. The live v2 form always selects an allowlisted category;
    // a false flag remains a canonical circuit value for API compatibility.
    if has_category {
        assert(category_id < CATEGORY_COUNT);
    } else {
        assert(category_id == 0);
    }

    // ---- commitment (v2 layout, v4 domain) ----
    let mut preimage: [Field; PREIMAGE_LEN] = [0; PREIMAGE_LEN];
    preimage[0] = DOMAIN_SEPARATOR;
    preimage[1] = challenge;
    preimage[2] = record_id_hash;
    preimage[3] = schema_version as Field;
    preimage[4] = commitment_blinding;
    preimage[5] = amount_cents as Field;
    preimage[6] = category_id as Field;
    preimage[7] = if has_category { 1 } else { 0 };
    preimage[8] = name_length as Field;
    for i in 0..MAX_NAME_BYTES {
        preimage[9 + i] = name_bytes[i] as Field;
    }
    let commitment = Poseidon2::hash(preimage, PREIMAGE_LEN);

    // ---- encrypt ----
    let plaintext = pack(name_bytes, name_length, amount_cents, category_id, has_category);
    let mut ciphertext: [Field; CIPHERTEXT_LEN] = [0; CIPHERTEXT_LEN];
    for i in 0..CIPHERTEXT_LEN {
        ciphertext[i] = plaintext[i] + Poseidon2::hash([enc_key, enc_nonce, i as Field], 3);
    }
    let mut mac_input: [Field; CIPHERTEXT_LEN + 3] = [0; CIPHERTEXT_LEN + 3];
    mac_input[0] = DS_MAC;
    mac_input[1] = enc_key;
    mac_input[2] = enc_nonce;
    for i in 0..CIPHERTEXT_LEN {
        mac_input[i + 3] = ciphertext[i];
    }
    let mac = Poseidon2::hash(mac_input, CIPHERTEXT_LEN + 3);

    (commitment, ciphertext, mac)
}

// Plaintext packing (8 fields):
//   fields[0..3]: name bytes, 30 bytes per field, little-endian
//   field[4]: amount (bits 0..63) | category (64..127) | has_category (128)
//             | name_length (129..160)
//   fields[5..7]: zero
pub fn pack(
    name_bytes: [u8; MAX_NAME_BYTES], name_length: u32, amount_cents: u64,
    category_id: u64, has_category: bool,
) -> [Field; CIPHERTEXT_LEN] {
    let mut plaintext: [Field; CIPHERTEXT_LEN] = [0; CIPHERTEXT_LEN];
    for f in 0..4 {
        let mut acc: Field = 0;
        let mut mult: Field = 1;
        for b in 0..BYTES_PER_FIELD {
            acc += (name_bytes[f * BYTES_PER_FIELD + b] as Field) * mult;
            mult *= 256;
        }
        plaintext[f] = acc;
    }
    let mut meta: Field = amount_cents as Field;
    meta += (category_id as Field) * 18446744073709551616;
    if has_category {
        meta += 340282366920938463463374607431768211456;
    }
    meta += (name_length as Field) * 680564733841876926926749214863536422912;
    plaintext[4] = meta;
    plaintext
}

// ------------------------------------------------------------------------
// Tests (run with `nargo test`; CI job zkp-v4 runs them).
// ------------------------------------------------------------------------

global ROOT: Field = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd;
global SALT: Field = 0x55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55;
global CHALLENGE: Field = 111;
global RID: Field = 222;

fn coffee() -> [u8; MAX_NAME_BYTES] {
    let mut bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    let letters = [67, 111, 102, 102, 101, 101];
    for i in 0..6 {
        bytes[i] = letters[i];
    }
    bytes
}

fn run(root: Field, nonce: Field, rid: Field, salt: Field, commit: Field) -> (Field, [Field; CIPHERTEXT_LEN], Field) {
    main(coffee(), 6, 4599, 1, true, 333, root, nonce, CHALLENGE, rid, SCHEMA_VERSION, commit, salt)
}

#[test]
fn honest_key_passes() {
    let (_, ct, mac) = run(ROOT, nonce_of(RID), RID, SALT, key_commitment_of(ROOT, SALT));
    // Ciphertext decrypts back to the packed plaintext under the derived key.
    let k = enc_key_of(ROOT, RID);
    let pt = pack(coffee(), 6, 4599, 1, true);
    for i in 0..CIPHERTEXT_LEN {
        assert(ct[i] - Poseidon2::hash([k, nonce_of(RID), i as Field], 3) == pt[i]);
    }
    assert(mac != 0);
}

#[test(should_fail_with = "key commitment mismatch")]
fn random_key_fails() {
    let _ = run(0xdeadbeef, nonce_of(RID), RID, SALT, key_commitment_of(ROOT, SALT));
}

#[test(should_fail_with = "key commitment mismatch")]
fn wrong_salt_fails() {
    let _ = run(ROOT, nonce_of(RID), RID, SALT + 1, key_commitment_of(ROOT, SALT));
}

#[test(should_fail_with = "nonce mismatch")]
fn wrong_record_id_hash_fails() {
    // Witness built for record RID, statement claims record RID + 1.
    let _ = run(ROOT, nonce_of(RID), RID + 1, SALT, key_commitment_of(ROOT, SALT));
}

#[test(should_fail_with = "nonce mismatch")]
fn nonce_mismatch_fails() {
    let _ = run(ROOT, nonce_of(RID) + 1, RID, SALT, key_commitment_of(ROOT, SALT));
}

#[test(should_fail)]
fn v2_validation_still_applies_zero_amount() {
    let _ = main(coffee(), 6, 0, 1, true, 333, ROOT, nonce_of(RID), CHALLENGE, RID, SCHEMA_VERSION, key_commitment_of(ROOT, SALT), SALT);
}

#[test(should_fail)]
fn wrong_schema_version_fails() {
    let _ = main(coffee(), 6, 4599, 1, true, 333, ROOT, nonce_of(RID), CHALLENGE, RID, 3, key_commitment_of(ROOT, SALT), SALT);
}

// Prints fixture values for scripts/zkp_v4_e2e.sh (nargo test --show-output).
#[test]
fn print_fixture() {
    let other_root: Field = 0x0fedcba9876543210fedcba9876543210fedcba9876543210fedcba98765;
    let commit = key_commitment_of(ROOT, SALT);
    let other_commit = key_commitment_of(other_root, SALT);
    let nonce = nonce_of(RID);
    println(f"FIXTURE commit={commit} other_commit={other_commit} nonce={nonce}");
}
