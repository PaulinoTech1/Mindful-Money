# Production Readiness

**Date:** 2026-10-12
**Current status:** Hardening controls landed; not yet production-ready for real financial data. Independent review and operational verification remain open.
**Goal:** Suitable for personal use with real data under an explicitly accepted residual-risk posture.

## What changed on 2026-10-12

The following controls were implemented (see individual docs for residual limitations):

- Higher Argon2id parameters + 60-bit entropy floor for new vaults (`docs/OFFLINE_ATTACK_COST.md`)
- Bucketed padding of sealed records
- `__Host-` cookie prefix (production)
- Recovery key mechanism (`docs/RECOVERY.md`)
- ZKP v3 encryption binding (`docs/ZKP_BINDING.md`)
- JS integrity layer: SRI attributes, manifest, CI hash checks (`docs/JS_INTEGRITY.md`)
- Prototype status banner and supporting docs

## Remaining blockers before real data

| Item | Status | Notes |
|------|--------|-------|
| Independent security review | Not started | Crypto paths, ZKP, session, deploy pipeline. **This is the primary blocker.** |
| End-to-end production deploy verification | Pending | Confirm health checks, integrity smoke tests, and migration application in the live environment |
| Backup restore test | Documented, not exercised | Procedure in `docs/BACKUP_RESTORE.md`; has not been tested against real data |
| Dependency hash pinning | Done | `requirements-hashed.txt` with SHA-256; Dockerfile uses `--require-hashes`; CI fails on HIGH/CRITICAL |
| Uptime monitoring | Documented, not configured | Setup steps in `docs/UPTIME_MONITORING.md`; operator must create the check manually |
| Full re-encryption recovery flow | Done | Automatic re-encryption implemented; see `docs/RECOVERY.md` for exact steps |

## Already in place (strengths)

- Client-side encryption with documented residual risks
- WebAuthn passkeys separate from encryption key
- Tenant isolation by `identity_id`
- Append-only audit events
- Strict CSP, CSRF, rate limiting, step-up for destructive actions
- Honest residual-risk documentation
- Recovery key with automatic re-encryption (ciphertext-only on server)
- JS integrity: SRI + manifest + CI smoke-test hash verification (fails deploy on mismatch)
- Hashed dependencies with CI vulnerability scanning
- Health/ready endpoints with documented monitoring setup
- Neon backup restore procedure documented

## What "production-ready for personal use" requires

- Independent review of the crypto and trust boundaries, or an explicit written acceptance of the residual risks by the operator
- Confirmed successful deploy of the hardened revision with migrations applied
- Tested backup restore procedure
- Operational monitoring that detects downtime or integrity failures

It does **not** require:
- SOC 2, HIPAA, or multi-user SaaS readiness
- 99.99% uptime
- Formal compliance certification

## Recommended next steps

1. Deploy the current `main` and verify the integrity smoke tests and health endpoints succeed.
2. Exercise a Neon branch restore against synthetic data and document the procedure.
3. Commission or perform a focused review of the key-derivation, sealing, recovery, and JS integrity paths.
4. Update this document and `PROTOTYPE_STATUS.md` once those items close.

Until the independent review is complete, treat the system as a hardened prototype. Do not store irreplaceable real financial data.

---

## Explicit operator acceptance

If you choose to store real financial data before an independent review is complete, you must explicitly accept:

1. **A fully compromised origin or deploy pipeline can replace the served JavaScript and exfiltrate your passphrase or plaintext.** The SRI, manifest, and CI checks raise the bar but do not defeat simultaneous compromise of the git repo and CI pipeline. This is the dominant residual risk.

2. **No third party has audited the cryptography.** The Argon2id parameters, NaCl sealed boxes, Poseidon2 circuit, and recovery key mechanism are implemented to best practices but have not undergone professional review.

3. **The recovery key is a single point of failure.** If you lose both your passphrase and your 32-word recovery key, your data is permanently unrecoverable. There is no backdoor.

4. **SimpleFin and your bank see your financial data in plaintext.** Mindful Money only excludes its own server, not the data providers.

5. **Neon and Google Cloud have infrastructure-level access to ciphertext.** They cannot decrypt it, but they can delete it or deny access.

6. **Backup restore has been documented but not tested.** The procedure in `docs/BACKUP_RESTORE.md` is theoretical until exercised.

By storing real data, you accept these risks as stated. This acceptance should be explicit, written, and revisited after any significant code change.
