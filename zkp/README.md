# Manual expense zero-knowledge proof (`manual-expense-v1`)

Reduces (does not eliminate -- see "What this does not prove" below) the
residual risk that a modified client can submit ciphertext with
semantically invalid manual-expense content that the server, by design,
cannot decrypt to check.

## Status: implemented, **not compiled or executed in this repository**

Every file here (`src/main.nr`, the tests in it, `zkp_verifier.py`,
`static/zkp/manual_expense_client.js`) was written against real, current,
cited API documentation and version pins -- not from memory. None of it has
been compiled, proved, or verified in this session, because the toolchain
this circuit needs (`nargo`, `bb`) has no native Windows build, and this
repository's dev environment is native Windows (not WSL). See the project's
delivery report for the exact evidence.

Concretely, right now:

- `nargo test` (the circuit tests at the bottom of `src/main.nr`) has not
  been run. They are reviewed, not verified.
- No `target/manual_expense.json` circuit artifact exists, so
  `static/zkp/manual_expense_client.js` has nothing to load and cannot
  actually generate a proof yet.
- No verification key exists, so `zkp_verifier.py`'s `bb verify` call has
  nothing to verify against and will raise a clear
  `CircuitArtifactsUnavailable` error rather than silently accepting or
  rejecting proofs.
- The existing (non-ZK) manual-expense entry flow added previously (the
  "Add manual expense" dialog, `submitManualExpense` in `static/app.js`,
  plain `POST /api/records`) is **unchanged and still fully functional**.
  This ZK path is additive: `POST /api/records/manual` (see `app.py`) and
  its challenge endpoint exist, are unit-tested at the Flask-orchestration
  level (`test_zkp_server.py`, using a stub verifier -- see that file's
  docstring), and are ready to be wired to a real proof once a circuit
  artifact exists. The UI does not call it yet.

## Toolchain versions

| Tool | Version | Source |
|---|---|---|
| `nargo` / Noir compiler | `>=1.0.0-beta.20` | See rationale below |
| `bb` / Barretenberg | `3.0.0-nightly.20251104` | Confirmed compatible with nargo 1.0.0-beta.20 |
| `@noir-lang/noir_js` | `1.0.0-beta.20` | pinned in `static/zkp/package.json` |
| `@aztec/bb.js` | `3.0.0-nightly.20251104` | pinned in `static/zkp/package.json` |
| `poseidon` (Noir stdlib package) | `v0.1.1` | git dependency in `Nargo.toml` |

**Why beta.20, not beta.15**: the official example app
(`noir-lang/tiny-noirjs-app`, fetched directly from GitHub while writing
this) pins `@noir-lang/noir_js@1.0.0-beta.15` with
`@aztec/bb.js@3.0.0-nightly.20251104`. However, a filed upstream issue
(`AztecProtocol/aztec-packages#18270`) reports that `bbup` -- the tool that
resolves a compatible Barretenberg version for an installed `nargo` --
resolves nargo `1.0.0-beta.15` to a **null** Barretenberg version, i.e. no
mapping exists for that exact pairing via the standard install path. The
same search turned up an explicit confirmation that nargo
`1.0.0-beta.20` pairs correctly with Barretenberg
`3.0.0-nightly.20251104`. Pinning to beta.20 avoids a known-broken install
path; if you have evidence beta.15 now works via `bbup -nv 1.0.0-beta.15`,
that's a one-line change to this file, `Nargo.toml`, and
`static/zkp/package.json`.

Note: `@noir-lang/acvm_js` and `@noir-lang/noirc_abi` (siblings `noir_js` imports at runtime, per the official example app) are pinned to `1.0.0-beta.20` in `static/zkp/package.json` by inference -- Noir's monorepo releases these together, but this session did not independently confirm `1.0.0-beta.20` is actually published for those two specific packages. Run `npm view @noir-lang/acvm_js versions` / `npm view @noir-lang/noirc_abi versions` before `npm install` and adjust if beta.20 isn't there.

**This entire stack is beta/nightly**, not a stable release line. That is
an accurate description of where Noir/Barretenberg tooling currently is
for a browser-proving UltraHonk workflow, not a corner cut in this
implementation. Re-pin to stable tags as soon as they exist and this
circuit has been re-verified against them -- do not assume beta.20's
behavior carries forward unchanged.

## Build commands (to run on Linux, macOS, or WSL -- NOT native Windows)

```bash
# 1. Install nargo (the Noir compiler)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup --version 1.0.0-beta.20

# 2. Install bb (Barretenberg), matched to the installed nargo version
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
bbup   # auto-resolves to 3.0.0-nightly.20251104 for nargo 1.0.0-beta.20

# 3. Compile the circuit (from zkp/manual_expense/)
cd zkp/manual_expense
nargo compile
# -> produces target/manual_expense.json (ACIR bytecode + ABI)

# 4. Run circuit tests
nargo test --show-output

# 5. Generate the verification key (from the compiled artifact)
bb write_vk --scheme ultra_honk -b target/manual_expense.json -o target/vk
sha256sum target/manual_expense.json target/vk   # record and pin both hashes

# 6. Install and build the browser client bundle
cd ../../static/zkp
npm install
npm run build   # produces the bundle static/app.js's manual-expense flow will load
```

## Deploying the verification key (server side)

`zkp_verifier.py` reads the verification key from
`ZKP_MANUAL_EXPENSE_VK_PATH` (default `zkp/manual_expense/target/vk`) and
refuses to start verifying proofs if that file is absent -- see
`CircuitArtifactsUnavailable` in that module. **The server must never
accept a verification key from a request.** Only the file at this
server-controlled, read-only path is trusted; see `zkp_verifier.py` and the
final report's "Verification trust anchor" section for why.

## What this circuit does and does not prove

Proves (see `src/main.nr` for the exact constraints and the adversarial
tests at the bottom of that file):

- the hidden amount, in integer cents, is `> 0` and `<= MAX_AMOUNT_CENTS`
- the hidden name occupies `1..=120` UTF-8 **bytes** inside a fixed
  120-byte buffer, with every byte past the declared length forced to zero
- the hidden category is either "no category" or one of the 11 allowlisted
  category IDs
- the public `commitment` is the Poseidon2 hash of all of the above, plus
  the server-issued `challenge`, `record_id_hash`, and `schema_version`,
  under an explicit domain separator -- so the proof cannot be replayed
  against a different challenge/record/schema by simply relabeling public
  inputs

Does **not** prove:

- that the name is `<= 120` Unicode **code points** (that's a code-point
  bound enforced by `validateExpenseName` in `static/app.js`; the circuit
  only sees UTF-8 bytes and cannot cheaply parse Unicode boundaries -- see
  the comment in `main.nr`)
- that the AES/sealed-box ciphertext submitted alongside the proof
  actually contains this same private record. This is the single most
  important limitation of this design -- see the final report's "Residual
  risks" and `test_zkp_server.py`'s `test_proof_ciphertext_mismatch_*`
  test, which is required to stay in the suite specifically to document
  this gap, not to hide it.
