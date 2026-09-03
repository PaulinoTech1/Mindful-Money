# Manual-expense zero-knowledge validation

`manual-expense-v1` proves that a hidden manual-expense record satisfies
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
manual_expense.json  f8577b04b5ced4823c79beb822572f7f2a377de0c6acefc84771c1437e1023e9
vk                   aa119aab46bb92a9be27db89819221c703141ff4412e0be509e86d2fbc34730e
vk_hash              bbb2fe47eed1e3acc28d636bd884ee40ade721e68b1456ed7eb094c72846a7f5
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
3. `schema_version == 1`
4. public return value `commitment`

The circuit enforces a non-empty, well-formed UTF-8, canonical zero-padded
name; rejects ASCII controls, invalid/overlong sequences, surrogates, and
outer ASCII spaces; bounds the amount to 1..99,999,999,999 cents; checks
category membership; and fixes the schema version. It returns:

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
2. Call `proveManualExpense(challenge, validatedRecord)`.
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

The current live `static/app.js` manual-entry path is still the original
non-ZK path. The ZK module and endpoints are complete and tested, but UI
wiring should remain feature-gated until the proving bundle's roughly
3.4 MB gzip download and browser memory/latency are acceptable for alpha.
