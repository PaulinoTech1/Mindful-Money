# ZKP Encryption Binding (v3)

## Problem (v2 gap)

The v2 circuit (`manual-transaction-v2`) proved that a private witness
(name/amount/category) satisfied validation rules, and output a Poseidon2
commitment. However, the sealed ciphertext was produced separately via
`crypto_box_seal` (X25519). A malicious client could submit a valid proof
for record A's plaintext while uploading ciphertext for a different record B.
The server could not detect this mismatch.

## Solution (v3)

The v3 circuit (`manual-transaction-v3`) uses a ZK-friendly AEAD based on
the Poseidon2 sponge. The ciphertext is a **public output of the circuit**,
so the proof cryptographically binds the validated plaintext to the stored
ciphertext.

### Circuit: `zkp/manual_expense_sealed/src/main.nr`

**Private witness:**
- `name_bytes[120]`, `name_length`, `amount_cents`, `category_id`, `has_category`
  (same validation as v2)
- `commitment_blinding` (for the commitment scheme)
- `enc_key: Field` (derived from vault key, never leaves browser)
- `enc_nonce: Field` (random per record, stored publicly)

**Public inputs:**
- `challenge`, `record_id_hash`, `schema_version` (= 3)

**Public outputs:**
- `commitment: Field` (same Poseidon2 commitment as v2)
- `ciphertext: [Field; 8]` (encrypted plaintext)
- `mac: Field` (authentication tag)

### Encryption: Poseidon stream cipher

```
plaintext[0..3] = name bytes, 30 bytes/field, little-endian
plaintext[4] = amount | category<<64 | has_category<<128 | name_length<<129
plaintext[5..7] = 0 (padding)

keystream[i] = Poseidon2(enc_key, enc_nonce, i)
ciphertext[i] = plaintext[i] + keystream[i]  (field addition)

mac = Poseidon2(enc_key, enc_nonce, ciphertext[0..7])
```

This is a standard sponge-based stream cipher. Security relies on Poseidon2
being a pseudorandom function, which is the standard assumption for
ZK-friendly hashing.

### Key derivation (browser only)

```
enc_key = bytes_to_field(BLAKE2b("mindful-money-zkp-enc-v1" || privateKey || record_id)[:31])
```

- Domain-separated from all other key uses
- Bound to the specific record (different key per record)
- 31 bytes ensures the value is < BN254 field modulus
- The server never sees `enc_key` or `privateKey`

### Security properties

**What v3 guarantees:**
- The stored ciphertext decrypts (under a key the prover knows) to the
  exact plaintext that was validated by the circuit
- A malicious client cannot substitute a different ciphertext; the proof
  would fail verification because the public ciphertext output wouldn't match
- The MAC prevents ciphertext tampering after proof generation
- All records encrypt to the same size (8 fields), hiding plaintext length

**What v3 does NOT guarantee:**
- The prover used the "correct" key (derived from their vault key). A
  malicious prover could use a random key, but then they couldn't decrypt
  their own record. This doesn't affect other users or the server.
- The plaintext is "true" (the circuit validates format, not veracity).
  A user can still enter a fake transaction amount; the proof only shows
  it's well-formed.

### Why not prove X25519 in-circuit?

The v2 records use `crypto_box_seal` (X25519 + XSalsa20-Poly1305). Proving
this in a Noir circuit would require:
- X25519 scalar multiplication: ~1000+ constraints (elliptic curve ops)
- Salsa20: thousands of constraints (ARX cipher, not ZK-friendly)
- Total: likely 50,000+ constraints, slow proving, large circuit

The Poseidon-based AEAD achieves the same binding property with ~500
constraints (8 Poseidon hashes for keystream + 1 for MAC + packing logic).

### Migration from v2

- v2 proofs continue to verify (backward compatible)
- New ZKP-bound records should use v3
- The `crypto_box_seal` path remains for non-ZKP records (it's a standard,
  audited construction; the ZKP binding is only needed where proofs are used)

### Compilation

Requires Noir toolchain (nargo) and Barretenberg (bb):

```bash
cd zkp/manual_expense_sealed
nargo compile
# Generate proving/verification keys with bb
# See zkp/README.md for the full workflow
```

### Testing

- `zkp/test_v3_packing.py`: Verifies field packing/unpacking logic
- Circuit tests: `nargo test` (requires nargo)
- End-to-end: browser proof generation + server verification (requires bb)

## Files

- `zkp/manual_expense_sealed/src/main.nr` - v3 circuit
- `zkp/manual_expense_sealed/Nargo.toml` - package manifest
- `static/zkp/manual_expense_sealed_client.js` - browser client
- `zkp/test_v3_packing.py` - packing logic tests
