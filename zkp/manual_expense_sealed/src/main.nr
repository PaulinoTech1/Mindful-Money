// PaulinoTech Mindful Money -- sealed manual transaction circuit.
// circuit_version: "manual-transaction-v3"
//
// This circuit CLOSES the encryption-binding gap documented in the v2
// circuit. It proves, without revealing them:
//
//   "I know a name/amount/category tuple satisfying the application's
//    validation rules, AND I know an encryption key such that the public
//    `ciphertext` output is the Poseidon-sponge encryption of that tuple
//    under the key, AND the public `mac` authenticates the ciphertext."
//
// The server stores exactly the circuit-output ciphertext. A malicious
// client cannot submit a valid proof for record A's plaintext while
// uploading ciphertext for a different record B, because the ciphertext
// is a public output of the proof itself.
//
// Encryption: Poseidon2-based stream cipher.
//   keystream[i] = Poseidon2(enc_key, enc_nonce, i)[0]
//   ciphertext[i] = plaintext_fields[i] + keystream[i]
//   mac = Poseidon2(enc_key, enc_nonce, ciphertext[0..7])[0]
//
// The enc_key is derived by the client from the vault key via BLAKE2b
// (see static/app.js). It is a private witness; the server never sees it.
// The security property is: "the stored ciphertext decrypts (under a key
// the prover knows) to the proven plaintext." The server does not need to
// know the key.
//
// Plaintext packing (8 field elements, fixed size):
//   fields[0..3]: name bytes, 30 bytes per field (120 bytes total)
//   field[4]: amount_cents (64 bits) | category_id (64 bits) | flags (8 bits) | name_length (32 bits)
//   fields[5..7]: zero padding (reserved for future use)
//
// This also provides length-hiding: all records encrypt to the same size.

use poseidon::poseidon2::Poseidon2;

global MAX_NAME_BYTES: u32 = 120;
global CATEGORY_COUNT: u64 = 16;
global MAX_AMOUNT_CENTS: u64 = 99999999999;
global SCHEMA_VERSION: u64 = 3;
global DOMAIN_SEPARATOR: Field = 0x5041554c494e4f544543485f4d414e55414c5f54585f5633;
global PREIMAGE_LEN: u32 = MAX_NAME_BYTES + 9;
// Ciphertext is 8 field elements (fixed size for all records)
global CIPHERTEXT_LEN: u32 = 8;
// 30 bytes per field (240 bits, safely under BN254 modulus)
global BYTES_PER_FIELD: u32 = 30;

fn main(
    // ---- private witness: constructed in the browser, never sent to Flask ----
    name_bytes: [u8; MAX_NAME_BYTES],
    name_length: u32,
    amount_cents: u64,
    category_id: u64,
    has_category: bool,
    commitment_blinding: Field,
    // ---- encryption key material (private) ----
    enc_key: Field,
    enc_nonce: Field,
    // ---- public inputs: independently re-checked by Flask ----
    challenge: pub Field,
    record_id_hash: pub Field,
    schema_version: pub u64,
) -> pub (Field, [Field; CIPHERTEXT_LEN], Field) {
    assert(schema_version == SCHEMA_VERSION);

    // ---- validate name/amount/category (same as v2) ----
    assert(name_length >= 1);
    assert(name_length <= MAX_NAME_BYTES);
    
    // Validate UTF-8 and reject control characters (simplified from v2;
    // full validation logic copied from manual_expense/src/main.nr)
    let mut continuation_bytes: u8 = 0;
    for i in 0..MAX_NAME_BYTES {
        let b = name_bytes[i];
        if i < name_length {
            if continuation_bytes > 0 {
                assert(b >= 0x80 & b <= 0xBF);
                continuation_bytes -= 1;
            } else {
                assert(b >= 0x20); // reject control chars
                assert(b != 0x7F); // reject DEL
                if b >= 0xC2 & b <= 0xDF {
                    continuation_bytes = 1;
                } else if b >= 0xE0 & b <= 0xEF {
                    continuation_bytes = 2;
                } else if b >= 0xF0 & b <= 0xF4 {
                    continuation_bytes = 3;
                } else {
                    assert(b <= 0x7F);
                }
            }
        } else {
            assert(b == 0); // padding must be zero
        }
    }
    assert(continuation_bytes == 0);

    // Validate amount
    assert(amount_cents >= 1);
    assert(amount_cents <= MAX_AMOUNT_CENTS);

    // Validate category
    if has_category {
        assert(category_id < CATEGORY_COUNT);
    }

    // ---- compute commitment (same as v2 for compatibility) ----
    let mut preimage: [Field; PREIMAGE_LEN] = [0; PREIMAGE_LEN];
    for i in 0..MAX_NAME_BYTES {
        preimage[i] = name_bytes[i] as Field;
    }
    preimage[MAX_NAME_BYTES] = name_length as Field;
    preimage[MAX_NAME_BYTES + 1] = amount_cents as Field;
    preimage[MAX_NAME_BYTES + 2] = category_id as Field;
    preimage[MAX_NAME_BYTES + 3] = has_category as Field;
    preimage[MAX_NAME_BYTES + 4] = commitment_blinding;
    preimage[MAX_NAME_BYTES + 5] = challenge;
    preimage[MAX_NAME_BYTES + 6] = record_id_hash;
    preimage[MAX_NAME_BYTES + 7] = DOMAIN_SEPARATOR;
    preimage[MAX_NAME_BYTES + 8] = SCHEMA_VERSION as Field;
    let commitment = Poseidon2::hash(preimage, PREIMAGE_LEN);

    // ---- pack plaintext into fixed field array ----
    let mut plaintext: [Field; CIPHERTEXT_LEN] = [0; CIPHERTEXT_LEN];
    
    // Pack name bytes: 30 bytes per field, little-endian
    for f in 0..4 {
        let mut acc: Field = 0;
        let mut mult: Field = 1;
        for b in 0..BYTES_PER_FIELD {
            let idx = f * BYTES_PER_FIELD + b;
            if idx < MAX_NAME_BYTES {
                acc += (name_bytes[idx] as Field) * mult;
                mult *= 256;
            }
        }
        plaintext[f] = acc;
    }
    
    // Pack metadata into field 4:
    // bits 0-63: amount_cents, bits 64-127: category_id,
    // bit 128: has_category, bits 129-160: name_length
    // 2^64 = 18446744073709551616, 2^128 = 340282366920938463463374607431768211456
    // 2^129 = 680564733841876926926749214863536422912
    let mut meta: Field = amount_cents as Field;
    meta += (category_id as Field) * 18446744073709551616;
    if has_category {
        meta += 340282366920938463463374607431768211456;
    }
    meta += (name_length as Field) * 680564733841876926926749214863536422912;
    plaintext[4] = meta;
    
    // Fields 5-7 remain zero (padding/reserved)

    // ---- encrypt with Poseidon stream cipher ----
    let mut ciphertext: [Field; CIPHERTEXT_LEN] = [0; CIPHERTEXT_LEN];
    for i in 0..CIPHERTEXT_LEN {
        let ks_input: [Field; 3] = [enc_key, enc_nonce, i as Field];
        let keystream = Poseidon2::hash(ks_input, 3);
        ciphertext[i] = plaintext[i] + keystream;
    }

    // ---- compute authentication tag ----
    let mut mac_input: [Field; CIPHERTEXT_LEN + 2] = [0; CIPHERTEXT_LEN + 2];
    mac_input[0] = enc_key;
    mac_input[1] = enc_nonce;
    for i in 0..CIPHERTEXT_LEN {
        mac_input[i + 2] = ciphertext[i];
    }
    let mac = Poseidon2::hash(mac_input, CIPHERTEXT_LEN + 2);

    (commitment, ciphertext, mac)
}
