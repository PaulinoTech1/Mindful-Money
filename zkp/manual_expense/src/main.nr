// PaulinoTech Mindful Money -- manual expense record commitment circuit.
// circuit_version: "manual-expense-v1"
//
// Proves, without revealing them:
//   "I know a name/amount/category/blinding tuple that satisfies this
//    application's validation rules, and whose Poseidon2 commitment --
//    bound to a server-issued challenge and record context -- equals the
//    public `commitment` value."
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
// Housing, Groceries, Dining, Transport, Utilities, Subscriptions,
// Shopping, "Health & insurance", Investing, Income, Uncategorized --
// must stay in exact sync with MANUAL_CATEGORIES in static/app.js and
// CATEGORY_IDS in zkp_verifier.py. Changing the taxonomy is a breaking
// circuit change (new circuit_version), not a config tweak.
global CATEGORY_COUNT: u64 = 11;
// $999,999,999.99 in cents -- must stay in sync with MANUAL_AMOUNT_MAX in
// static/app.js.
global MAX_AMOUNT_CENTS: u64 = 99999999999;
global SCHEMA_VERSION: u64 = 1;
// Big-endian integer encoding of the 29 ASCII bytes "PAULINOTECH_MANUAL_EXPENSE_V1"
// (< the BN254 scalar field modulus). Recompute with:
//   python3 -c "print(hex(int.from_bytes(b'PAULINOTECH_MANUAL_EXPENSE_V1','big')))"
// Never reuse this constant for a different record type's commitment --
// that is the entire point of domain separation.
global DOMAIN_SEPARATOR: Field = 0x5041554c494e4f544543485f4d414e55414c5f455850454e53455f5631;
global PREIMAGE_LEN: u32 = MAX_NAME_BYTES + 8;

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
    commitment: pub Field,
) {
    assert(schema_version == SCHEMA_VERSION);

    // ---- name bound ----------------------------------------------------
    // Bounds UTF-8 *bytes*, not Unicode *code points*. The browser UI's
    // "1 to 120 characters" promise (static/app.js validateExpenseName) is
    // a code-point bound; a 120-character name using multi-byte UTF-8 can
    // exceed 120 bytes. That check stays in the browser; this circuit
    // enforces the byte-level bound only. Documented, not silently glossed
    // over -- see ../README.md.
    assert(name_length >= 1);
    assert(name_length <= MAX_NAME_BYTES);
    // Every byte at or past the declared length must be zero. Without
    // this, two different (name_bytes, name_length) witnesses -- one
    // short with garbage trailing bytes, one long -- could both look like
    // valid inputs to a careless circuit while committing to ambiguous
    // "name" values. This constraint removes that ambiguity: exactly one
    // canonical buffer shape corresponds to any given logical name.
    for i in 0..MAX_NAME_BYTES {
        if i >= name_length {
            assert(name_bytes[i] == 0);
        }
    }

    // ---- amount bound ----------------------------------------------------
    assert(amount_cents > 0);
    assert(amount_cents <= MAX_AMOUNT_CENTS);

    // ---- category membership ----------------------------------------------
    // has_category separates "no category selected" (validateExpenseCategory's
    // `undefined`) from "Uncategorized" chosen explicitly. Both are legitimate
    // canonical states but are different witnesses, so both are constrained
    // explicitly rather than silently collapsed into one before proving.
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
    preimage[7] = name_length as Field;
    for i in 0..MAX_NAME_BYTES {
        preimage[8 + i] = name_bytes[i] as Field;
    }
    let computed_commitment = Poseidon2::hash(preimage, PREIMAGE_LEN);
    assert(computed_commitment == commitment);
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
    category_id: u64, blinding: Field, challenge: Field, record_id_hash: Field,
) -> Field {
    let mut preimage: [Field; PREIMAGE_LEN] = [0; PREIMAGE_LEN];
    preimage[0] = DOMAIN_SEPARATOR;
    preimage[1] = challenge;
    preimage[2] = record_id_hash;
    preimage[3] = SCHEMA_VERSION as Field;
    preimage[4] = blinding;
    preimage[5] = amount_cents as Field;
    preimage[6] = category_id as Field;
    preimage[7] = name_length as Field;
    for i in 0..MAX_NAME_BYTES {
        preimage[8 + i] = name_bytes[i] as Field;
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
    let commitment = build_preimage(name_bytes, name_length, amount_cents, category_id, blinding, challenge, record_id_hash);
    main(name_bytes, name_length, amount_cents, category_id, true, blinding, challenge, record_id_hash, SCHEMA_VERSION, commitment);
}

#[test]
fn accepts_minimum_amount_one_cent() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 1, 0, 5, 1, 2);
    main(name_bytes, name_length, 1, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test]
fn accepts_exact_maximum_amount() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, MAX_AMOUNT_CENTS, 0, 5, 1, 2);
    main(name_bytes, name_length, MAX_AMOUNT_CENTS, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn rejects_zero_amount() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 0, 0, 5, 1, 2);
    main(name_bytes, name_length, 0, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn rejects_amount_above_maximum() {
    let (name_bytes, name_length) = valid_name();
    let over = MAX_AMOUNT_CENTS + 1;
    let commitment = build_preimage(name_bytes, name_length, over, 0, 5, 1, 2);
    main(name_bytes, name_length, over, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn rejects_zero_length_name() {
    let name_bytes: [u8; MAX_NAME_BYTES] = [0; MAX_NAME_BYTES];
    let commitment = build_preimage(name_bytes, 0, 500, 0, 5, 1, 2);
    main(name_bytes, 0, 500, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn rejects_name_length_above_maximum() {
    let (name_bytes, _) = valid_name();
    let commitment = build_preimage(name_bytes, MAX_NAME_BYTES + 1, 500, 0, 5, 1, 2);
    main(name_bytes, MAX_NAME_BYTES + 1, 500, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn rejects_nonzero_byte_past_declared_length() {
    let (mut name_bytes, name_length) = valid_name();
    // A byte at index 6 (>= declared length 6) that is not zero: the
    // "ambiguous trailing bytes" attack this circuit exists to prevent.
    name_bytes[6] = 88;
    let commitment = build_preimage(name_bytes, name_length, 500, 0, 5, 1, 2);
    main(name_bytes, name_length, 500, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test]
fn accepts_every_valid_category_with_has_category_true() {
    let (name_bytes, name_length) = valid_name();
    for category_id in 0..CATEGORY_COUNT {
        let commitment = build_preimage(name_bytes, name_length, 500, category_id, 5, 1, 2);
        main(name_bytes, name_length, 500, category_id, true, 5, 1, 2, SCHEMA_VERSION, commitment);
    }
}

#[test(should_fail)]
fn rejects_out_of_range_category() {
    let (name_bytes, name_length) = valid_name();
    let bad_category = CATEGORY_COUNT; // one past the last valid id
    let commitment = build_preimage(name_bytes, name_length, 500, bad_category, 5, 1, 2);
    main(name_bytes, name_length, 500, bad_category, true, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test]
fn accepts_no_category_selected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, 5, 1, 2);
    main(name_bytes, name_length, 500, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn rejects_wrong_schema_version() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, 5, 1, 2);
    main(name_bytes, name_length, 500, 0, false, 5, 1, 2, SCHEMA_VERSION + 1, commitment);
}

// ---- commitment binding: changing any one input must change the commitment ----

#[test(should_fail)]
fn changing_amount_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, 5, 1, 2);
    // Same commitment, different amount -- must fail: proves the
    // commitment actually depends on amount_cents.
    main(name_bytes, name_length, 501, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn changing_name_after_commitment_is_computed_is_rejected() {
    let (mut name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, 5, 1, 2);
    name_bytes[0] = 90; // mutate the name after the commitment was fixed
    main(name_bytes, name_length, 500, 0, false, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn changing_category_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 1, 5, 1, 2);
    main(name_bytes, name_length, 500, 2, true, 5, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn changing_blinding_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, 5, 1, 2);
    main(name_bytes, name_length, 500, 0, false, 6, 1, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn changing_challenge_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, 5, 1, 2);
    // Same witness, same commitment, but presented against a different
    // public challenge -- must fail: proves a proof cannot be replayed
    // against a different server-issued challenge by simply relabeling it.
    main(name_bytes, name_length, 500, 0, false, 5, 9, 2, SCHEMA_VERSION, commitment);
}

#[test(should_fail)]
fn changing_record_id_after_commitment_is_computed_is_rejected() {
    let (name_bytes, name_length) = valid_name();
    let commitment = build_preimage(name_bytes, name_length, 500, 0, 5, 1, 2);
    main(name_bytes, name_length, 500, 0, false, 5, 1, 9, SCHEMA_VERSION, commitment);
}

// ---- malicious-client simulation: bypass the browser entirely, hand-craft a witness ----
// This is the primary reason this circuit exists: the browser's
// validateExpenseName/validateExpenseAmount/validateExpenseCategory (see
// static/app.js) are never consulted here at all. These tests build
// `main`'s arguments directly, exactly as a hand-rolled malicious prover
// would, bypassing every layer of JS validation entirely.

#[test(should_fail)]
fn malicious_client_cannot_prove_amount_zero() {
    let (name_bytes, name_length) = valid_name();
    let forged_commitment = build_preimage(name_bytes, name_length, 0, 0, 999, 1, 2);
    main(name_bytes, name_length, 0, 0, false, 999, 1, 2, SCHEMA_VERSION, forged_commitment);
}

#[test(should_fail)]
fn malicious_client_cannot_prove_amount_over_maximum() {
    let (name_bytes, name_length) = valid_name();
    let forged_amount = MAX_AMOUNT_CENTS + 100000;
    let forged_commitment = build_preimage(name_bytes, name_length, forged_amount, 0, 999, 1, 2);
    main(name_bytes, name_length, forged_amount, 0, false, 999, 1, 2, SCHEMA_VERSION, forged_commitment);
}

#[test(should_fail)]
fn malicious_client_cannot_prove_invalid_category() {
    let (name_bytes, name_length) = valid_name();
    let forged_category = 255;
    let forged_commitment = build_preimage(name_bytes, name_length, 500, forged_category, 999, 1, 2);
    main(name_bytes, name_length, 500, forged_category, true, 999, 1, 2, SCHEMA_VERSION, forged_commitment);
}

#[test(should_fail)]
fn malicious_client_cannot_prove_invalid_name_length() {
    let name_bytes: [u8; MAX_NAME_BYTES] = [65; MAX_NAME_BYTES]; // all 'A', length 0 claimed
    let forged_commitment = build_preimage(name_bytes, 0, 500, 0, 999, 1, 2);
    main(name_bytes, 0, 500, 0, false, 999, 1, 2, SCHEMA_VERSION, forged_commitment);
}
