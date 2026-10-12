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
| Independent security review | Not started | Crypto paths, ZKP, session, deploy pipeline |
| End-to-end production deploy verification | Pending | Confirm health checks, integrity smoke tests, and migration application in the live environment |
| Backup restore test | Not done | Neon PITR exists; has not been exercised against real ciphertext |
| Full re-encryption recovery flow | Incomplete | Recovery decrypts the seed; automatic re-encryption of existing records is not implemented |
| Dependency pinning + scanning | Partial | Dependabot and hash pinning not yet confirmed in CI |
| Uptime monitoring + alerting | Not confirmed | Health endpoint exists; Cloud Monitoring check not documented as live |

## Already in place (strengths)

- Client-side encryption with documented residual risks
- WebAuthn passkeys separate from encryption key
- Tenant isolation by `identity_id`
- Append-only audit events
- Strict CSP, CSRF, rate limiting, step-up for destructive actions
- Honest residual-risk documentation
- Recovery key (ciphertext-only on server)
- JS integrity mechanisms that raise the bar for accidental tampering

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
