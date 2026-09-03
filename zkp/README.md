# Manual-transaction zero-knowledge validation

`manual-transaction-v2` proves that a hidden manual income or expense record satisfies
the application's schema and range rules. The server verifies the proof
before storing the opaque ciphertext and never receives the plaintext,
encryption key, passphrase, or private witness.

## Verified status

This implementation was built and exercised with the exact pinned stack:

| Component | Version |
|---|---:|
| Noir / Nargo / noir.js | `1.0.0-beta.26` |
| Barretenberg / `@aztec/bb.js` | `5.1.0` |
| Poseidon package source | `v0.2.6` plus the documented beta.26 compatibility patch |

The following checks passed on 2026-09-03:

- all 28 Noir circuit tests, including direct malicious-witness and UTF-8 tests
- `nargo compile`, producing the committed ACIR artifact
- browser-package production bundling with Vite
- a real 14,656-byte UltraHonk proof generated and self-verified by
  `@aztec/bb.js` 5.1.0
- native `bb` 5.1.0 verification of that bb.js proof using the committed VK
- 28 Flask/server verifier tests
- 114 browser end-to-end checks, including encrypted income/expense entry and
  strict type-specific category dropdowns with `Other`
- `npm audit --omit=dev`: zero production dependency advisories

The full npm audit reports six low-severity advisories under the official
Vite Node-polyfill development plugin's unused crypto-browserify tree. They
are not present in the production dependency audit; no forced downgrade or
security-control weakening was applied to hide them.

The production bundle is intentionally not committed. It is about 10 MB
uncompressed because it includes the proving WASM; load it only when a
user enters the proof-gated workflow.

Barretenberg's browser worker needs `SharedArrayBuffer`. Flask now sends
`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp` on the app and same-origin
assets so that capability is available without weakening CSP.

## Files

- `manual_expense/src/main.nr`: private-input constraints and public
  Poseidon2 commitment output
- `manual_expense/target/manual_expense.json`: compiled ACIR + ABI
- `manual_expense/target/vk`: server verification key
- `vendor/poseidon-v0.2.6-beta26`: narrowly scoped v0.2.6 compatibility
  package
- `../static/zkp/manual_expense_client.js`: browser witness/prover code
- `../static/zkp/smoke_prove.mjs`: real bb.js-to-native-bb interop smoke proof
- `../zkp_verifier.py`: fail-closed native CLI verifier
- `../app.py`: authenticated, CSRF-protected challenge and storage endpoints

Committed artifact SHA-256 values:

```text
manual_expense.json  cb0d6e69e917ff28ca54b043bfd86b0a2d71d4ea53dafb0f6a1af07dc0f27511
vk                   0a091b74379aa3fcca4d37b469ecf4400fb225045b3bdada6269298a975854cd
vk_hash              c0453957ec104b991d9f7b1993fb2d0deaa2ce7f52689f2b918658f74c796dc9
```

Regenerate the ACIR and VK together after any circuit, dependency, or
compiler change. Never accept a VK supplied by a request.

## Statement proved

Private witness:

- `name_bytes: [u8; 120]`
- `name_length: u32`
- `amount_cents: u64`
- `category_id: u64`
- `has_category: bool`
- `commitment_blinding: Field`

Public statement, in the exact order emitted by the compiled ABI:

1. server-issued `challenge`
2. server-issued `record_id_hash`
3. `schema_version == 2`
4. public return value `commitment`

The circuit enforces a non-empty, well-formed UTF-8, canonical zero-padded
name; rejects ASCII controls, invalid/overlong sequences, surrogates, and
outer ASCII spaces; bounds the amount to 1..99,999,999,999 cents; checks
category membership; distinguishes income categories from expense categories;
and fixes the schema version. Expense category ids are 0..9 and income category
ids are 10..15. Each type has a separate internal `Other` id, so choosing
`Other` still binds the transaction type even though both display the same
user-facing label. It returns:

```text
Poseidon2(domain_separator, challenge, record_id_hash, schema_version,
          blinding, amount_cents, category_id, has_category, name_length,
          name_bytes[0..120])
```

Noir's `u8`, `u32`, `u64`, and `bool` witness decoding provides native
type/range constraints. The explicit assertions enforce the tighter
application rules. A hostile witness fails during Noir execution and no
proof can be generated for it.

The browser normalizes names to NFC and limits them to 120 Unicode code
points before proving. The circuit proves valid UTF-8 and a stricter
120-byte storage bound, but does not prove NFC normalization or count code
points; those Unicode properties would require substantially more circuit
logic.

## Browser request flow

1. Call `requestChallenge(api)`.
2. Call `proveManualTransaction(challenge, validatedRecord)` (the legacy
   `proveManualExpense` export remains as an alias).
3. Add the returned `blinding` and `publicContext` to the plaintext record.
4. Encrypt that plaintext using the existing browser-only encryption code.
5. Submit this shape to `POST /api/records/manual`:

```js
{
  challenge_id: challenge.challenge_id,
  blind_index,
  sealed,
  commitment: proofResult.commitment,
  proof: proofResult.proof,
  public_inputs: proofResult.publicInputs,
}
```

The client takes the commitment from Noir's public return value. It also
requires bb.js to emit exactly the expected four public inputs and performs
a local proof self-check before submission.

## Server verification

Flask atomically consumes the challenge, reconstructs all four public
inputs from server-owned context plus the submitted commitment, and rejects
missing, extra, reordered, non-canonical, or out-of-field values. The
verifier writes 32-byte big-endian field arrays and invokes:

```bash
bb verify -s ultra_honk -p proof -i public_inputs -k /server/controlled/vk
```

Only exit status zero is acceptance. Missing artifacts, timeout, malformed
proofs, and execution errors all fail closed.

Set these production variables:

```text
ZKP_BB_EXECUTABLE=/opt/barretenberg-5.1.0/bb
ZKP_MANUAL_EXPENSE_VK_PATH=/srv/app/zkp/manual_expense/target/vk
ZKP_VERIFY_TIMEOUT_SECONDS=10
```

## Reproducible build

On Linux/macOS with exact `nargo` and `bb` binaries installed:

```bash
bash scripts/build_zkp.sh
```

The script refuses any Nargo version other than beta.26 or any bb version
other than 5.1.0, then runs the circuit suite, compiles, regenerates the VK,
locks npm dependencies, builds the browser bundle, and runs the real proof
smoke test. Nargo cannot express a prerelease such as beta.26 in
`compiler_version`; the script's version check is therefore the effective
compiler pin.

### Poseidon v0.2.6 compatibility

Unmodified `noir-lang/poseidon` v0.2.6 does not compile with Noir beta.26:
it calls the former two-argument `poseidon2_permutation(state, 4)` API and
uses an empty-slice form rejected by the newer compiler. The local package
retains v0.2.6's static Poseidon2 hash algorithm and applies only the new
one-argument permutation signature. The untouched pinned upstream source
is present at `zkp/upstream/poseidon` for comparison.

## Critical limitation: ciphertext is not proved

This proof establishes knowledge of a valid plaintext whose Poseidon2 hash
is the public commitment. It does **not** establish that the separately
submitted `sealed` ciphertext encrypts that same plaintext. A modified
client can prove valid record A and submit ciphertext B.

The legitimate client mitigates stored corruption by encrypting the
blinding/context and calling `verifyStoredRecord()` after decryption before
rendering. That is client-side detection, not server-side prevention.
Server-enforced binding requires the circuit to prove the encryption
relation itself (or use a ZK-friendly authenticated-encryption design);
AES-GCM/sealed-box ciphertext cannot be bound merely by adding its hash as
a public input.

The live `static/app.js` manual-entry form now accepts either income or expense,
uses a strict type-specific category list with `Other`, and stores the selected
type only inside the encrypted record. Its storage path is still non-ZK. The ZK
module and endpoints are complete and tested, but UI wiring should remain
feature-gated until the proving bundle's roughly 3.4 MB gzip download and browser
memory/latency are acceptable for alpha.
