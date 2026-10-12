# Offline Attack Cost Analysis

**Date:** 2026-10-12
**Status:** Current (KDF v2: Argon2id MODERATE)

## KDF Parameters

| Version | Algorithm | Ops | Memory | Description |
|---------|-----------|-----|--------|-------------|
| v1 | Argon2id | 2 | 64 MB | Legacy (libsodium INTERACTIVE) |
| v2 | Argon2id | 3 | 256 MB | Previous (libsodium MODERATE) |
| v3 | Argon2id | 5 | 512 MB | Current (aggressive) |

New vaults use v3. Existing vaults keep their version until the user
explicitly upgrades (to avoid lockout from parameter mismatch).
If a browser cannot allocate 512MB (e.g., mobile), the client automatically
falls back to v2 for that session and notifies the user.

## Passphrase Requirements

- Minimum length: 12 characters
- Minimum estimated entropy: 60 bits (enforced for new vaults)
- Existing vaults: weak passphrases generate a warning, not a block

## Attack Cost Model

### Assumptions

- Attacker has the encrypted database (offline attack)
- Attacker uses high-end GPUs (e.g., RTX 4090 class)
- Argon2id with 256MB memory is memory-bound, not compute-bound
- Each GPU can test ~50,000 passphrases/second (conservative estimate for
  Argon2id with 256MB; actual throughput is lower due to memory bandwidth)

### 60-bit passphrase vs Argon2id v3 (512MB, 5 ops)

- Search space: 2^60 ≈ 1.15 × 10^18 passphrases
- Attacker with 10,000 GPUs: ~15,000 guesses/second/GPU (memory-bound at 512MB)
  = 1.5 × 10^8 guesses/second total
- Time to exhaust: 1.15 × 10^18 / 1.5 × 10^8 ≈ 7.7 × 10^9 seconds
- **≈ 244 years** to exhaust, **≈ 122 years** on average

### 60-bit passphrase vs Argon2id v2 (256MB, 3 ops) - for comparison

- Attacker with 10,000 GPUs: 10,000 × 50,000 = 5 × 10^8 guesses/second
- **≈ 73 years** to exhaust, **≈ 36 years** on average

### 80-bit passphrase (recommended: 6-word diceware)

- Search space: 2^80 ≈ 1.2 × 10^24
- Same attacker: **≈ 76 million years** on average

### Comparison across versions (60-bit passphrase, 10k GPUs)

| Version | Avg. time to crack |
|---------|-------------------|
| v1 (64MB, 2 ops) | **≈ 9 years** |
| v2 (256MB, 3 ops) | **≈ 36 years** |
| v3 (512MB, 5 ops) | **≈ 122 years** |

The jump from v2 to v3 is ~3.4x. Diminishing returns apply: the 60-bit
entropy floor matters more than KDF tuning beyond this point.

## Memory-Hardness Rationale

Argon2id's memory requirement (256MB per hash) is the primary defense:
- ASICs cannot economically implement 256MB of fast memory per core
- GPUs are limited by memory bandwidth, not compute units
- The 4x memory increase from v1 to v2 provides ~4x attack cost increase
  even before considering the additional iteration

## Limitations

1. **Weak passphrases bypass all KDF protection.** A 40-bit passphrase
   (e.g., "Password123!") falls in hours regardless of KDF parameters.
   The 60-bit minimum mitigates this for new vaults.

2. **Quantum computers** do not significantly speed up Argon2id or
   symmetric encryption (Grover's algorithm provides only quadratic
   speedup; 256-bit keys remain secure).

3. **Side channels** (timing, cache, power) are out of scope for this
   analysis. The browser WASM implementation may leak via cache timing.

4. **The server never sees the passphrase.** This analysis assumes the
   attacker obtained the encrypted database through server compromise
   or backup theft.

## Recommendations

- Use a diceware passphrase (6+ words) or a password manager
- Enable the recovery key mechanism (see docs/RECOVERY.md)
- Upgrade v1 vaults to v2 when convenient (requires re-encryption)
