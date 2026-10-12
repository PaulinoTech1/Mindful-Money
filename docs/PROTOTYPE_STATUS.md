# Prototype Status

**Status:** Research prototype - NOT for real financial data

## What this means

Mindful Money is an experimental privacy-focused finance tracker. It is
not ready for production use with real financial data.

## Blockers for production use

### Must fix before real data

1. **JS integrity verification** (in progress)
   - Subresource Integrity hashes for all scripts
   - Signed manifest with out-of-band verification
   - Deploy-time hash verification in CI
   - Until this exists, the privacy claim is conditional on deployment integrity:
     a compromised server could silently replace the crypto code.

2. **KDF hardening** (done 2026-10-12)
   - Argon2id raised to MODERATE (3 ops, 256MB)
   - 60-bit minimum passphrase entropy enforced for new vaults
   - See docs/OFFLINE_ATTACK_COST.md

3. **Independent security review** (not started)
   - No third-party audit has been performed
   - The ZKP circuits, crypto implementation, and server code need
     professional review before handling real data.

### Completed hardening

- [x] Argon2id MODERATE parameters (v2)
- [x] Passphrase entropy gate (60-bit minimum)
- [x] Sealed record padding (bucketed lengths)
- [x] __Host- cookie prefix (production)
- [x] ZKP binding to ciphertext (v3 circuit)
- [x] Encrypted recovery key mechanism
- [x] Session revocation race fix
- [x] Anonymous rate limiting by IP

### Still needed

- [ ] JS integrity: SRI + signed manifest + CI verification
- [ ] Independent security audit
- [ ] Formal threat model review

## What IS safe to do now

- Run the test suite
- Experiment with test data
- Review the code
- Contribute improvements

## What is NOT safe yet

- Storing real bank account data
- Storing real transaction history
- Using as a primary finance tracker
- Trusting the privacy guarantees against a sophisticated attacker

---

*This document is updated as hardening progresses. When all blockers are
resolved and an independent review is complete, this status will change.*
