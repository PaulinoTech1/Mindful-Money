# Offline Attack Cost Analysis

**Date:** 2026-10-12
**Status:** Current (KDF v2: Argon2id MODERATE)

## KDF Parameters

| Version | Algorithm | Ops | Memory | Description |
|---------|-----------|-----|--------|-------------|
| v1 | Argon2id | 2 | 64 MB | Legacy (libsodium INTERACTIVE) |
| v2 | Argon2id | 3 | 256 MB | Current (libsodium MODERATE) |

New vaults use v2. Existing v1 vaults keep v1 until the user explicitly upgrades
(to avoid lockout from parameter mismatch).

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

### 60-bit passphrase vs Argon2id-MODERATE

- Search space: 2^60 ≈ 1.15 × 10^18 passphrases
- Attacker with 10,000 GPUs: 10,000 × 50,000 = 5 × 10^8 guesses/second
- Time to exhaust: 1.15 × 10^18 / 5 × 10^8 ≈ 2.3 × 10^9 seconds
- **≈ 73 years** to exhaust, **≈ 36 years** on average

### 80-bit passphrase (recommended: 6-word diceware)

- Search space: 2^80 ≈ 1.2 × 10^24
- Same attacker: **≈ 76 million years** on average

### Comparison: v1 (INTERACTIVE, 64MB)

- GPU throughput: ~200,000 guesses/second (4x faster due to lower memory)
- 60-bit passphrase vs 10,000 GPUs: **≈ 9 years** on average
- This is why v2 is the default for new vaults.

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
