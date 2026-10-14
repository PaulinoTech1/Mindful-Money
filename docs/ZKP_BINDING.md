# ZKP Encryption and Key Binding (v4)

Status labels follow `docs/ASVS.md`: implemented, locally tested,
CI-verified, production-verified, reviewed. Nothing here is reviewed by a
third party.

## Summary

| Circuit | Accepted for new records | Status |
|---|---|---|
| `manual-transaction-v2` (`zkp/manual_expense`) | No (read-only) | Validates a private witness and returns a commitment; does not bind the stored ciphertext. Existing v2 records stay readable. |
| `manual-transaction-v3` | Never | Removed. It bound the ciphertext to the proof, but its encryption key was a free witness: a proof made with any random key verified (reproduced locally on 2026-10-14 with nargo 1.0.0-beta.26 and bb 5.1.0). It was never wired to the server and never reached production. |
| `manual-transaction-v4` (`zkp/manual_expense_v4`) | Yes, once the vault enrolls | Binds the key to a per-vault commitment registered at enrollment. Wired into `static/app.js` (this PR). Implemented, locally tested; CI-verified once the PR checks pass; not production-verified. |

Earlier versions of this document said v2 proofs "continue to verify" and
implied v3 was in use. Neither was true in production: the image shipped no
`bb` binary or verification key, so every proof request failed closed with
503, and no code path produced v3 proofs.

## What v4 proves

Private witness (never leaves the browser): name bytes, name length,
amount, category, commitment blinding, `zk_root`, `enc_nonce`.

Public inputs, all filled by Flask from its own rows, never from the
request: `challenge`, `record_id_hash`, `schema_version` (4),
`key_commitment`, `vault_salt`.

Public outputs: `commitment` (v2 layout, v4 domain), `ciphertext[8]`, `mac`.

Constraints added over v2 validation (`zkp/manual_expense_v4/src/main.nr`):

```
key_commitment == P2(DS_KEY, zk_root, vault_salt)
enc_key         = P2(DS_ENC, zk_root, record_id_hash)      (computed in-circuit)
enc_nonce      == P2(DS_NONCE, record_id_hash)
ciphertext[i]   = plaintext[i] + P2(enc_key, enc_nonce, i)
mac             = P2(DS_MAC, enc_key, enc_nonce, ciphertext[0..7])
```

P2 is Poseidon2 (Noir `poseidon` v0.2.6, the same function as bb.js
`poseidon2Hash`; checked by `static/zkp/v4_client.test.mjs`). All domain
separators are distinct ASCII labels.

**Security argument.** To produce a valid proof for the statement the
server builds, a prover must know a `zk_root` whose Poseidon2 commitment
equals the value stored for this vault. Finding a different one is a
Poseidon2 second preimage. Because `enc_key` and the nonce are derived
inside the circuit from that root and the server-issued record id, the
prover cannot choose them, so the stored ciphertext is decryptable by the
vault owner and by nobody else who lacks the root. The server stores
exactly the proven outputs (`record_id || ciphertext || mac`), so the
ciphertext cannot be swapped after proving. Confidence: medium-high
(standard construction, but Poseidon2 as a PRF and this exact key schedule
are not third-party reviewed).

## Key derivation (browser only)

```
zk_root = BLAKE2b-256("mm-zkp-root-v1" || vault X25519 private key)[0..31]
```

248 bits, below the BN254 modulus. Derived in
`static/zkp/manual_expense_v4_core.js`; the private key and `zk_root` are
never sent. Intermediate buffers are zeroed; the resulting BigInt cannot be
(see `docs/HARDENING_PROPOSALS.md` R3).

## What the server learns

- `vault_salt`: 31 random bytes the server generated itself.
- `key_commitment`: one Poseidon2 output per vault.
- Per record: the proof, `record_id`, ciphertext, MAC, and the v2-style
  commitment, all public outputs.

It learns no plaintext, no key, and no passphrase. The commitment hides a
248-bit value, so it cannot be brute-forced directly.

**Argon2id offline-guess caveat.** `zk_root` is a deterministic function
of the passphrase (Argon2id, then X25519 key derivation, then BLAKE2b). So
anyone holding the commitment and salt can test a passphrase guess at the
cost of one Argon2id evaluation per guess. This is not a new leak: the
server already holds sealed records and blind indexes, which allow the
same Argon2id-bound offline test. The commitment does not make guessing
cheaper. Cost figures: `docs/OFFLINE_ATTACK_COST.md`. Confidence: high.

## Server flow (`app.py`)

1. Enrollment, step-up gated (`require_destructive_management`: passkey
   plus a recent assertion):
   `POST /api/zkp/key-commitment/salt` issues a server-random salt;
   `POST /api/zkp/key-commitment` stores the browser-computed commitment.
   Both refuse once a commitment exists. The server cannot check the value
   against the key; a wrong value only locks the vault out of its own v4
   proofs. `GET /api/zkp/key-commitment` reports `registered` and the salt.
2. `POST /api/zkp/challenge`: 503 if the verifier is unavailable, 409 if
   the vault has no commitment; otherwise returns the challenge, record
   id, and the vault's own commitment and salt.
3. `POST /api/records/manual` takes `challenge_id`, `blind_index`,
   `proof`, `public_inputs`, and an optional opaque `meta` hex string.
   The first five public inputs must equal the server-built values; v2
   and v3 challenges are refused. On success the proven part
   (`record_id || ciphertext || mac`, 304 bytes) is built from the proof
   outputs and `meta` (if present) is concatenated after it.
4. Rekey (`/api/vault/rekey/commit`) must carry a new `zkp_key_commitment`
   exactly when one is registered and replaces it in the same transaction
   as the salts and records (same salt, new key). The v4 tag is not carried
   to re-encrypted records, because their ciphertext is no longer the
   proven one; v2 tags are carried as before.

## Availability

- **Verifier runtime in the image.** The Dockerfile build stage fetches bb
  5.1.0 and the first 2^17 points of the BN254 CRS over HTTPS, each pinned
  by sha256, runs `bb write_vk` to confirm the committed VK matches the
  committed circuit, and bakes the decompressed CRS into `/opt/zkp/crs`
  (read-only). Without a baked CRS, bb tries to download it over plain
  HTTP at request time and hangs (reproduced locally). The verifier now
  runs with no network access (locally tested with `unshare -n`; CI runs
  the same check inside the built image with `--network none`).
- **Image size.** About 40 MB added (bb 38 MB, CRS 2 MB, VK 4 KB). The
  exact delta is reported by the `docker-zkp` CI job.
- **Readiness.** `/ready` reports `"zkp": "available"` or `"unavailable"`
  and never fails on it: ZKP is an optional feature, and failing readiness
  would take down the whole app for one feature. Decision recorded here.
- **Challenge refund.** A challenge is claimed atomically before
  verification. If the verifier is unavailable or times out, the claim is
  undone and the client gets 503, so an outage does not burn challenges.
  An invalid proof still spends its challenge.
- **Costs (locally measured, 8 threads, native bb).** 21,826 gates; prove
  about 0.24 s; verify about 10 ms; proof 14,656 bytes.
- **Browser bundle and proving time (locally tested, headless Chromium
  1243, Playwright 1.63.0, this box on 2026-10-14).** One self-contained
  ES module (`static/zkp/build/mm-zkp-v4.js`): about 20.2 MB raw, about
  10.8 MB gzip (bb.js Wasm, Noir ACVM and ABI wasm, the compiled circuit,
  and the first 2^17 compressed BN254 CRS points, all inlined). Cold load
  about 0.27 s, warm load about 0.26 s; first prove about 7.1 s, warm prove
  about 3.7 to 5.0 s. CI job `browser-zkp-v4` prints the same numbers for
  the runner. Numbers are labeled locally tested, not production-verified.

## What v4 does NOT guarantee

- The plaintext is true. The circuit checks format, not veracity.
- That the commitment registered at enrollment was computed honestly. A
  client that registers garbage only harms its own vault.
- Anything about records that did not go through this path (SimpleFin,
  CSV, plain manual entry use NaCl sealed boxes).
- Anything about production traffic: this PR is not merged or deployed.

The residual risk for this feature is recorded once, in
`docs/THREAT_MODEL.md` (risk register, "ZKP proof gate").

## UI behavior

`static/app.js` (this PR). The private key and `zk_root` stay in the page.

**Lazy load.** The prover is not in the initial page. `index.html` holds a
`<template id="zkpProverTemplate">` with one `<script type="module"
integrity=... crossorigin>` pointing at `static/zkp/build/mm-zkp-v4.js`.
`app.js` clones that tag in when enrollment, proving or opening a v4
record needs it. The integrity hash pins every byte the prover runs
(wasm, CRS and circuit are all inlined). The page already ships
`Cross-Origin-Embedder-Policy: require-corp` and
`Cross-Origin-Opener-Policy: same-origin` for SharedArrayBuffer; the
prover itself is forced single-threaded and worker-free, so it does not
need SharedArrayBuffer. CSP already allows `'wasm-unsafe-eval'` under
`script-src` (required by the Barretenberg and Noir wasm compilers) and
`worker-src 'self'` (kept; unused by this bundle). Decision: keep
`wasm-unsafe-eval`; no other CSP change.

**Enrollment.** After unlock, `enrollZkpInBackground` tries enrollment
without prompting. If there is no passkey, or the passkey assertion is
stale, it stops quietly. The next manual entry that wants a v4 proof
retries with one passkey ceremony (`authenticateWithPasskey`). Both salt
and commitment endpoints stay step-up gated. Salt issuance is idempotent
while no commitment exists: a pending salt is reused so concurrent tabs
(or background enrollment racing a manual entry) commit over the same
salt and the stored commitment always matches the stored salt.

**Manual entry.** `submitManualTransaction` tries the v4 path first
(challenge, prove in the browser, submit with a sealed `meta` for id,
date, account and the other non-proven fields). Proven fields (name,
amount, category, type) come only from the decrypted proven part when
the record is opened. Fallback, chosen and kept zero-knowledge: if the
prover fails to load (network or SRI), the verifier is unavailable
(503), the vault has no usable enrollment (409 / stale step-up with no
passkey), or a proof cannot be generated in page, the form saves a
standard NaCl sealed-box record through `POST /api/records` and the UI
says so (`Saved encrypted without ZK validation (non-ZKP): ...`). A
rejected proof (400) is not a fallback: nothing is saved and the error
is shown. Confidence: high for the privacy of both paths; medium for
the UX of the fallback message.

**Decrypt.** `load` opens each row through `openRecord`: sealed boxes as
before, v4 rows through the prover's `decryptManualTransactionV4` plus
the sealed meta. If the prover cannot load, the sealed meta is still
opened with the candidate key so a wrong passphrase fails unlock even
when every stored record is v4; a correct key leaves that row counted as
"not shown" (same warning as a malformed record) rather than failing the
whole unlock.

**Rekey and recovery.** `reencryptForRekey` opens v4 rows with the old
`zk_root`, re-seals them as standard sealed boxes under the new key, and
sends a new `zkp_key_commitment` (same salt, new key) with the rekey
commit. The server already drops the v4 tag on those rows.

**Backup and restore.** Export already carries `commitment` /
`circuit_version`. Import of a v4 row on a vault that cannot prove
re-seals it as a standard sealed box before upload (the normal upsert
cannot carry the proof tag, and clears any leftover tag).

**Editing a v4 record.** The normal editor still uses `POST /api/records`.
That path now clears `commitment` and `circuit_version` on conflict, so
an edited former v4 record is no longer tagged as proven. Residual risk
of a stale tag without this clear is recorded here and nowhere else.

**Vault reset and force-overwrite of KDF salts.** Both clear the
commitment and salt, because the next passphrase is a new vault key. The
new key re-enrolls with a passkey step-up.

## Tests

| Test | What it shows | Label |
|---|---|---|
| `nargo test` in `zkp/manual_expense_v4` | honest passes; random key, wrong salt, wrong record id, nonce mismatch, zero amount, wrong schema fail with the expected assertion | locally tested; CI job `zkp-v4` |
| `scripts/zkp_v4_e2e.sh` | rebuild equals committed circuit and VK; honest bb proof verifies; a random-key proof checked against the registered commitment exits nonzero; a record id swap exits nonzero | locally tested; CI job `zkp-v4` |
| `static/zkp/v4_client.test.mjs` | BLAKE2b root derivation, bb.js Poseidon2 equals Noir, honest bb.js proof has 15 public inputs in order, stored record decrypts, random key cannot produce a witness, tampering fails | locally tested; CI job `zkp-v4` |
| `test_zkp_server.py` | enrollment, challenge, submission, refund, readiness, verifier module, meta append, tag clear on upsert, reset and force-overwrite clear the commitment | locally tested; CI `verify` |
| `test_recovery_rekey.py` (ZKP cases) | commitment replaced atomically at rekey, refused when absent, v4 tag not carried | locally tested; CI `verify` |
| `test_integrity_script.py` | `generate_integrity.py` is idempotent (no duplicate crossorigin); committed HTML and manifest match files including the prover; inlined CRS matches the pinned hashes | locally tested; CI `verify` |
| `test_playwright_zkp_v4.py` | real Chromium: enroll, prove, store, decrypt into the ledger, random-key rejection, 503 and SRI fallbacks labeled non-ZKP, recovery rekey with a v4 record, no plaintext / private key / zk_root / third-party CRS in the network capture, proving-time numbers | locally tested; CI job `browser-zkp-v4` |
| `docker-zkp` CI job | image builds with pinned downloads; fixture proof verifies inside the container with no network | CI only |
| `zkp-v4` CI "rebuild equals committed" | `npm run build:browser` reproduces `static/zkp/build/mm-zkp-v4.js` | CI only |

## Files

- `zkp/manual_expense_v4/` circuit, tests, compiled artifact, `vk`, `vk_hash`
- `static/zkp/manual_expense_v4_core.js`, `manual_expense_v4_client.js`,
  `manual_expense_v4_browser.js`, `vite.browser.config.js`,
  `build/mm-zkp-v4.js` (committed, SRI-pinned), `v4_client.test.mjs`
- `zkp/browser_crs/` first 2^17 compressed G1 points and G2 (sha256-pinned;
  inlined into the browser bundle, not shipped in the Docker image)
- `zkp_verifier.py`, `app.py` (endpoints above), `models.py`,
  `migrations/versions/b8c9d0e1f2a3_add_zkp_key_commitment.py`
- `scripts/zkp_v4_e2e.sh`, `scripts/fetch_zkp_runtime.py`, `Dockerfile`
- `tests/fixtures/zkp_v4/` honest proof fixture for fixed test values
