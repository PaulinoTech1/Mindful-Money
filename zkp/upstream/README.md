# ZKP upstream dependency workspace

This directory collects the three upstream source repositories relevant to
Mindful Money's experimental manual-expense proof in one place. They are Git
submodules pinned to immutable release commits; their source histories and
build artifacts are not copied into the main application repository.

## Pinned sources

| Directory | Upstream | Release examined | Pinned commit | Role |
|---|---|---|---|---|
| `noir/` | `noir-lang/noir` | `v1.0.0-beta.26` | `40d6574f851d926f93e0c3a271bac3e6e82ac905` | Noir language, Nargo compiler/package manager, ACIR toolchain |
| `aztec-packages/` | `AztecProtocol/aztec-packages` | `v5.1.0` | `3ffc13a503b7bf321c3578399074938c75f2ac7e` | Barretenberg native prover/verifier and browser `bb.js` backend |
| `poseidon/` | `noir-lang/poseidon` | `v0.2.6` | `00f879180a56720169cff92a56778d40678d8e26` | Poseidon/Poseidon2 circuit hash library |

These are inspection pins, not a claim that this exact three-way version set
is compatible. The application currently pins older beta/nightly versions in
`../manual_expense/Nargo.toml` and `../../static/zkp/package.json`. Do not
change those production-facing pins until the circuit tests, browser proof,
native verification, and proof/public-input serialization have passed together
with one recorded toolchain set.

## Initialize this workspace

After cloning Mindful-Money:

```bash
git switch ZKP
git submodule update --init --depth 1
```

To confirm that the expected commits—not moving upstream branches—are checked
out:

```bash
git submodule status
git -C zkp/upstream/noir rev-parse HEAD
git -C zkp/upstream/aztec-packages rev-parse HEAD
git -C zkp/upstream/poseidon rev-parse HEAD
```

## Dependency entry points

### Noir / Nargo

- `noir/Cargo.toml` and `noir/Cargo.lock`: Rust workspace dependencies.
- `noir/package.json` and `noir/yarn.lock`: JavaScript tooling dependencies.
- `noir/EXTERNAL_NOIR_LIBRARIES.yml`: upstream's external Noir library index.
- `noir/compiler/`, `noir/tooling/`, and `noir/acvm-repo/`: compiler, developer
  tooling, and ACIR/ACVM implementation.
- `noir/LICENSE-MIT` and `noir/LICENSE-APACHE`: upstream licensing.

### Barretenberg and bb.js

- `aztec-packages/barretenberg/cpp/`: native proving and verification backend.
- `aztec-packages/barretenberg/ts/`: source for the `@aztec/bb.js` package.
- `aztec-packages/barretenberg/ts/package.json`: direct JavaScript dependencies
  and build/test commands.
- `aztec-packages/barretenberg/ts/package-lock.json` and
  `aztec-packages/barretenberg/ts/yarn.lock`: resolved dependency graphs.
- `aztec-packages/barretenberg/bbup/`: the version-selection installer. Treat
  installer scripts as untrusted build inputs and review them before execution.
- `aztec-packages/barretenberg/LICENSE` and the package's declared license:
  inspect both before redistribution rather than assuming the monorepo has one
  uniform licensing rule.

### Poseidon

- `poseidon/Nargo.toml`: Noir compiler requirement and circuit dependencies.
- `poseidon/src/`: hash implementation under examination.
- `poseidon/package.json` and `poseidon/yarn.lock`: repository tooling.
- `poseidon/LICENSE`: upstream license.

## Mindful Money integration points

- `../manual_expense/src/main.nr`: the current circuit.
- `../manual_expense/Nargo.toml`: its Noir dependency pin.
- `../../static/zkp/package.json`: browser prover dependency pins.
- `../../static/zkp/manual_expense_client.js`: private witness construction and
  browser proof generation.
- `../../zkp_verifier.py`: server-controlled verification-key and `bb` boundary.
- `../../test_zkp_server.py`: Flask orchestration and fail-closed tests.

## Required compatibility gate

Before promoting anything from this branch:

1. Compile `manual_expense` with the selected Nargo release.
2. Run all Noir circuit tests.
3. Generate and hash the verification key with the matched `bb` release.
4. Generate a proof in the browser with the matched `noir_js` and `bb.js`.
5. Verify that exact browser proof with the native server-side verifier.
6. Confirm public-input ordering and proof-file serialization byte-for-byte.
7. Re-run Python security tests and browser end-to-end tests.

The proof remains experimental until that complete round trip passes. Merely
having the upstream source available does not validate the circuit or close the
documented ciphertext-to-witness binding limitation.
