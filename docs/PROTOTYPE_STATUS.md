# Prototype Status

**Status:** Research prototype with recent hardening — still not recommended for real financial data without an independent review

**Last updated:** 2026-10-12

## What this means

Mindful Money is an experimental privacy-focused finance tracker. Hardening landed on 2026-10-12, but residual risks remain that make it unsuitable as a primary store of real bank data until reviewed.

## Blockers for production use with real data

1. **Independent security review** (not started)
   - No third-party audit of the crypto paths, ZKP circuits, session handling, or deployment pipeline.
   - Required before treating residual risks as accepted.

2. **Full origin-compromise resistance** (partially mitigated)
   - SRI attributes, integrity manifest, and CI hash checks exist.
   - These do not defeat simultaneous compromise of the git repository and the CI/deploy pipeline.
   - See `docs/JS_INTEGRITY.md`.

3. **Operational verification**
   - First successful production deploy with the new controls has not been confirmed end-to-end.
   - Backup restore has not been exercised against real data.

## Completed hardening (2026-10-12)

- [x] Argon2id parameters raised for new vaults (see `docs/OFFLINE_ATTACK_COST.md`)
- [x] 60-bit minimum passphrase entropy enforced for new vaults
- [x] Sealed record padding to bucketed lengths
- [x] `__Host-` cookie prefix in production
- [x] ZKP v3 circuit that binds validated plaintext to stored ciphertext
- [x] Encrypted recovery key mechanism (with documented limitations)
- [x] JS integrity: SRI + manifest + CI smoke-test verification
- [x] Session revocation race condition fixed
- [x] Anonymous rate limiting by IP

## What IS safe to do now

- Run the test suite
- Experiment with synthetic/test data
- Review the code and residual-risk documents
- Contribute improvements

## What is NOT safe yet

- Storing real bank account data or transaction history as a primary record
- Relying on the privacy guarantees against a sophisticated attacker who can influence the served JavaScript
- Treating the recovery key as a complete solution (re-encryption flow is incomplete)

---

*This document is updated as the status changes. When an independent review is complete and the remaining operational items are closed, the status will be revised.*
