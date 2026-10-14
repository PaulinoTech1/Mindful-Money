# ZKP Encryption and Key Binding (v4)

Status labels follow `docs/ASVS.md`: implemented, locally tested,
CI-verified, production-verified, reviewed. Nothing here is reviewed by a
third party.

## Summary

| Circuit | Accepted for new records | Status |
|---|---|---|
| `manual-transaction-v2` (`zkp/manual_expense`) | No (read-only) | Validates a private witness and returns a commitment; does not bind the stored ciphertext. Existing v2 records stay readable. |
| `manual-transaction-v3` | Never | Removed. It bound the ciphertext to the proof, but its encryption key was a free witness: a proof made with any random key verified (reproduced locally on 2026-10-14 with nargo 1.0.0-beta.26 and bb 5.1.0). It was never wired to the server and never reached production. |
| `manual-transaction-v4` (`zkp/manual_expense_v4`) | Yes, once the vault enrolls | Binds the key to a per-vault commitment registered at enrollment. Implemented, locally tested; CI-verified once the PR checks pass; not production-verified. |

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
3. `POST /api/records/manual` takes only `challenge_id`, `blind_index`,
   `proof`, `public_inputs`. The first five public inputs must equal the
   server-built values; v2 and v3 challenges are refused. On success the
   record is built from the proof outputs.
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
  about 0.24 s; verify about 10 ms; proof 14,656 bytes. Browser bundle for
  the prover is about 18 MB (about 9.6 MB gzip), dominated by the Noir and
  Barretenberg WASM; browser proving time is not measured.

## What v4 does NOT guarantee

- The plaintext is true. The circuit checks format, not veracity.
- That the commitment registered at enrollment was computed honestly. A
  client that registers garbage only harms its own vault.
- Anything about records that did not go through this path (SimpleFin,
  CSV, plain manual entry use NaCl sealed boxes).
- UI integration: `static/app.js` does not call the v4 client yet. Until it
  does, no production records use v4 and the app's normal decrypt path
  would not open a v4 record. Wiring it in is the next step.

The residual risk for this feature is recorded once, in
`docs/THREAT_MODEL.md` (risk register, "ZKP proof gate").

## Tests

| Test | What it shows | Label |
|---|---|---|
| `nargo test` in `zkp/manual_expense_v4` | honest passes; random key, wrong salt, wrong record id, nonce mismatch, zero amount, wrong schema fail with the expected assertion | locally tested; CI job `zkp-v4` |
| `scripts/zkp_v4_e2e.sh` | rebuild equals committed circuit and VK; honest bb proof verifies; a random-key proof checked against the registered commitment exits nonzero; a record id swap exits nonzero | locally tested; CI job `zkp-v4` |
| `static/zkp/v4_client.test.mjs` | BLAKE2b root derivation, bb.js Poseidon2 equals Noir, honest bb.js proof has 15 public inputs in order, stored record decrypts, random key cannot produce a witness, tampering fails | locally tested; CI job `zkp-v4` |
| `test_zkp_server.py` | enrollment, challenge, submission, refund, readiness, verifier module, real bb check of a committed proof fixture | locally tested; CI `verify` and `zkp-v4` |
| `test_recovery_rekey.py` (ZKP cases) | commitment replaced atomically at rekey, refused when absent, v4 tag not carried | locally tested; CI `verify` |
| `docker-zkp` CI job | image builds with pinned downloads; fixture proof verifies inside the container with no network | CI only |

## Files

- `zkp/manual_expense_v4/` circuit, tests, compiled artifact, `vk`, `vk_hash`
- `static/zkp/manual_expense_v4_core.js`, `manual_expense_v4_client.js`, `v4_client.test.mjs`
- `zkp_verifier.py`, `app.py` (endpoints above), `models.py`,
  `migrations/versions/b8c9d0e1f2a3_add_zkp_key_commitment.py`
- `scripts/zkp_v4_e2e.sh`, `scripts/fetch_zkp_runtime.py`, `Dockerfile`
- `tests/fixtures/zkp_v4/` honest proof fixture for fixed test values
