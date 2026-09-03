// PaulinoTech Mindful Money -- manual transaction commitment circuit.
// circuit_version: "manual-transaction-v2"
//
// Proves, without revealing them:
//   "I know a name/amount/category/blinding tuple that satisfies this
//    application's validation rules, and whose Poseidon2 commitment --
//    bound to a server-issued challenge and record context -- is returned
//    as the public `commitment` output."
//
// Flask (see ../../zkp_verifier.py and app.py's /api/records/manual)
// verifies this proof and independently checks every public input against
// what it itself issued. Flask never receives name_bytes, amount_cents,
// category_id, or commitment_blinding in any form -- see ../README.md,
// "Privacy analysis", for the full list of what Flask does and does not
// learn.
//
// IMPORTANT LIMITATION (see ../README.md and the project's final report
// for the full writeup -- do not remove this comment, it documents a real,
// currently-unclosed gap): this circuit proves facts about a *private
// witness*. It does NOT prove that the sealed-box ciphertext submitted
// alongside the proof actually encrypts this same witness. A client that
// controls its own JS could submit a valid proof for record A's plaintext
// while uploading ciphertext for a different record B; Flask cannot detect
// that mismatch at ingestion time because it can't decrypt either one. The
// legitimate client detects it on next read (recomputed commitment !=
// stored commitment, record rejected -- see static/app.js). Proving the
// encryption relation itself (binding proof to ciphertext) is documented
// as a separate research item, not implemented here.

use poseidon::poseidon2::Poseidon2;

global MAX_NAME_BYTES: u32 = 120;
// Expense ids 0..9: Housing, Groceries, Dining, Transport, Utilities,
// Subscriptions, Shopping, "Health & insurance", Investing, Other.
// Income ids 10..15: Salary, Freelance, Investment income, Refund, Gift,
// Other. The separate Other ids bind the transaction type even though the
// browser displays the same label. Must stay in exact sync with the client
// and zkp_verifier.py. Taxonomy changes require a new circuit version.
global CATEGORY_COUNT: u64 = 16;
// $999,999,999.99 in cents -- must stay in sync with MANUAL_AMOUNT_MAX in
// static/app.js.
global MAX_AMOUNT_CENTS: u64 = 99999999999;
global SCHEMA_VERSION: u64 = 2;
// Big-endian integer encoding of the ASCII bytes "PAULINOTECH_MANUAL_TX_V2"
// (< the BN254 scalar field modulus). Recompute with:
//   python3 -c "print(hex(int.from_bytes(b'PAULINOTECH_MANUAL_TX_V2','big')))"
// Never reuse this constant for a different record type's commitment --
// that is the entire point of domain separation.
global DOMAIN_SEPARATOR: Field = 0x5041554c494e4f544543485f4d414e55414c5f54585f5632;
global PREIMAGE_LEN: u32 = MAX_NAME_BYTES + 9;

fn main(
    // ---- private witness: constructed in the browser, never sent to Flask ----
    name_bytes: [u8; MAX_NAME_BYTES],
    name_length: u32,
    amount_cents: u64,
    category_id: u64,
    has_category: bool,
    commitment_blinding: Field,
    // ---- public inputs: independently re-checked by Flask against what it issued ----
    challenge: pub Field,
    record_id_hash: pub Field,
    schema_version: pub u64,
) -> pub Field {
    assert(schema_version == SCHEMA_VERSION);

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

    // ---- commitment ----------------------------------------------------
    // Every witness value that must be bound to the commitment is listed
    // here explicitly. Nothing is computed and left unconstrained: an
    // underconstrained commitment (one that ignores a witness value) would
    // let a prover swap that value after the fact without invalidating the
    // proof -- exactly the defect ../tests and the "malicious client" test
    // in test_zkp_server.py are meant to catch.
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
    // Returning the commitment as `pub Field` makes it part of the
    // statement verified by Barretenberg. The browser takes this value
    // from Noir's decoded return value and checks that bb.js emits it as
    // the fourth public input.
    Poseidon2::hash(preimage, PREIMAGE_LEN)
}

// ------------------------------------------------------------------------
// Circuit tests. Written against current Noir `#[test]` syntax and
// intended to run via `nargo test` (see ../README.md) -- NOT executed in
// the environment this circuit was authored in (no native Windows nargo
// build exists; see the final report's toolchain section). Treat these as
// reviewed-but-unexecuted until run in CI/a Linux-or-macOS dev machine.
// ------------------------------------------------------------------------

fn valid_name() -> ([u8; MAX_NAME_BYTES], u32) {
    let mut bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    // "Coffee" -- ASCII, well within bounds.
    let letters = [67, 111, 102, 102, 101, 101];
    for i in 0..6 {
        bytes[i] = letters[i];
    }
    (bytes, 6)
}

fn build_preimage(
    name_bytes: [u8; MAX_NAME_BYTES], name_length: u32, amount_cents: u64,
    category_id: u64, has_category: bool, blinding: Field,
    challenge: Field, record_id_hash: Field,
) -> Field {
    let mut preimage: [Field; PREIMAGE_LEN] = [0; PREIMAGE_LEN];
    preimage[0] = DOMAIN_SEPARATOR;
    preimage[1] = challenge;
    preimage[2] = record_id_hash;
    preimage[3] = SCHEMA_VERSION as Field;
    preimage[4] = blinding;
    preimage[5] = amount_cents as Field;
    preimage[6] = category_id as Field;
    preimage[7] = if has_category { 1 } else { 0 };
    preimage[8] = name_length as Field;
    for i in 0..MAX_NAME_BYTES {
        preimage[9 + i] = name_bytes[i] as Field;
    }
    Poseidon2::hash(preimage, PREIMAGE_LEN)
}

#[test]
fn accepts_a_valid_record() {
    let (name_bytes, name_length) = valid_name();
    let challenge = 111;
    let record_id_hash = 222;
    let blinding = 333;
    let amount_cents: u64 = 4599;
    let category_id: u64 = 1; // Groceries
    let commitment = build_preimage(name_bytes, name_length, amount_cents, category_id, true, blinding, challenge, record_id_hash);
    assert(main(name_bytes, name_length, amount_cents, category_id, true, blinding, challenge, record_id_hash, SCHEMA_VERSION) == commitment);
}

#[test]
fn accepts_minimum_amount_one_cent() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 1, 0, false, 5, 1, 2);
    assert(main(name_bytes, name_length, 1, 0, false, 5, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test]
fn accepts_exact_maximum_amount() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, MAX_AMOUNT_CENTS, 0, false, 5, 1, 2);
    assert(main(name_bytes, name_length, MAX_AMOUNT_CENTS, 0, false, 5, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn rejects_zero_amount() {
    let (name_bytes, name_length) = valid_name();
    let _result = main(name_bytes, name_length, 0, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn rejects_amount_above_maximum() {
    let (name_bytes, name_length) = valid_name();
    let over = MAX_AMOUNT_CENTS + 1;
    let _result = main(name_bytes, name_length, over, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn rejects_zero_length_name() {
    let name_bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    let _result = main(name_bytes, 0, 500, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn rejects_name_length_above_maximum() {
    let (name_bytes, _) = valid_name();
    let _result = main(name_bytes, MAX_NAME_BYTES + 1, 500, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn rejects_nonzero_byte_past_declared_length() {
    let (mut name_bytes, name_length) = valid_name();
    // A byte at index 6 (>= declared length 6) that is not zero: the
    // "ambiguous trailing bytes" attack this circuit exists to prevent.
    name_bytes[6] = 88;
    let _result = main(name_bytes, name_length, 500, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test]
fn accepts_well_formed_multibyte_utf8_name() {
    let mut name_bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    // U+00E9 (é), encoded canonically as C3 A9.
    name_bytes[0] = 0xc3;
    name_bytes[1] = 0xa9;
    let commitment = build_preimage(name_bytes, 2, 500, 0, false, 5, 1, 2);
    assert(main(name_bytes, 2, 500, 0, false, 5, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn rejects_overlong_utf8_encoding() {
    let mut name_bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    name_bytes[0] = 0xc0;
    name_bytes[1] = 0x80;
    let _result = main(name_bytes, 2, 500, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn rejects_truncated_utf8_sequence() {
    let mut name_bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    name_bytes[0] = 0xe2;
    name_bytes[1] = 0x82;
    let _result = main(name_bytes, 2, 500, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn rejects_ascii_control_character() {
    let mut name_bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    name_bytes[0] = 0x0a;
    let _result = main(name_bytes, 1, 500, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn rejects_outer_ascii_space() {
    let mut name_bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    name_bytes[0] = 0x20;
    let _result = main(name_bytes, 1, 500, 0, false, 5, 1, 2, SCHEMA_VERSION);
}

#[test]
fn accepts_every_valid_category_with_has_category_true() {
    let (name_bytes, name_length) = valid_name();
    for category_id in 0..CATEGORY_COUNT {
        let commitment = build_preimage(name_bytes, name_length, 500, category_id, true, 5, 1, 2);
        assert(main(name_bytes, name_length, 500, category_id, true, 5, 1, 2, SCHEMA_VERSION) == commitment);
    }
}

#[test(should_fail)]
fn rejects_out_of_range_category() {
    let (name_bytes, name_length) = valid_name();
    let bad_category = CATEGORY_COUNT; // one past the last valid id
    let _result = main(name_bytes, name_length, 500, bad_category, true, 5, 1, 2, SCHEMA_VERSION);
}

#[test]
fn accepts_no_category_selected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, false, 5, 1, 2);
    assert(main(name_bytes, name_length, 500, 0, false, 5, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn rejects_wrong_schema_version() {
    let (name_bytes, name_length) = valid_name();
    let _result = main(name_bytes, name_length, 500, 0, false, 5, 1, 2, SCHEMA_VERSION + 1);
}

// ---- commitment binding: changing any one input must change the commitment ----

#[test(should_fail)]
fn changing_amount_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, false, 5, 1, 2);
    // Same commitment, different amount -- must fail: proves the
    // commitment actually depends on amount_cents.
    assert(main(name_bytes, name_length, 501, 0, false, 5, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn changing_name_after_commitment_is_computed_is_rejected() {
    let (mut name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, false, 5, 1, 2);
    name_bytes[0] = 90; // mutate the name after the commitment was fixed
    assert(main(name_bytes, name_length, 500, 0, false, 5, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn changing_category_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 1, true, 5, 1, 2);
    assert(main(name_bytes, name_length, 500, 2, true, 5, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn changing_category_presence_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, false, 5, 1, 2);
    // category_id 0 means no category when the flag is false, but Housing
    // when the flag is true. The flag must therefore be committed too.
    assert(main(name_bytes, name_length, 500, 0, true, 5, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn changing_blinding_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, false, 5, 1, 2);
    assert(main(name_bytes, name_length, 500, 0, false, 6, 1, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn changing_challenge_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, false, 5, 1, 2);
    // Same witness, same commitment, but presented against a different
    // public challenge -- must fail: proves a proof cannot be replayed
    // against a different server-issued challenge by simply relabeling it.
    assert(main(name_bytes, name_length, 500, 0, false, 5, 9, 2, SCHEMA_VERSION) == commitment);
}

#[test(should_fail)]
fn changing_record_id_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, false, 5, 1, 2);
    assert(main(name_bytes, name_length, 500, 0, false, 5, 1, 9, SCHEMA_VERSION) == commitment);
}

// ---- malicious-client simulation: bypass the browser entirely, hand-craft a witness ----
// This is the primary reason this circuit exists: the browser's
// validateTransactionName/validateTransactionAmount/validateTransactionCategory (see
// static/app.js) are never consulted here at all. These tests build
// `main`'s arguments directly, exactly as a hand-rolled malicious prover
// would, bypassing every layer of JS validation entirely.

#[test(should_fail)]
fn malicious_client_cannot_prove_amount_zero() {
    let (name_bytes, name_length) = valid_name();
    let _result = main(name_bytes, name_length, 0, 0, false, 999, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn malicious_client_cannot_prove_amount_over_maximum() {
    let (name_bytes, name_length) = valid_name();
    let forged_amount = MAX_AMOUNT_CENTS + 100000;
    let _result = main(name_bytes, name_length, forged_amount, 0, false, 999, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn malicious_client_cannot_prove_invalid_category() {
    let (name_bytes, name_length) = valid_name();
    let forged_category = 255;
    let _result = main(name_bytes, name_length, 500, forged_category, true, 999, 1, 2, SCHEMA_VERSION);
}

#[test(should_fail)]
fn malicious_client_cannot_prove_invalid_name_length() {
    let name_bytes: [u8; MAX_NAME_BYTES] = [65; MAX_NAME_BYTES]; // all 'A', length 0 claimed
    let _result = main(name_bytes, 0, 500, 0, false, 999, 1, 2, SCHEMA_VERSION);
}
