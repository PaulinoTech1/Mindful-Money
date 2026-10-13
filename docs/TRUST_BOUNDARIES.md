# Trust Boundaries

**Last updated:** 2026-10-12
**Status:** Honest assessment, not marketing

This document states exactly what Mindful Money protects against and what it does not. Do not describe the app as "zero-knowledge" without these qualifiers.

## What the server cannot see

The Flask backend never receives:
- Plaintext transaction data (encrypted in browser before upload)
- SimpleFin credentials or access URLs (handled entirely client-side)
- Vault passphrases or derived encryption keys
- Financial amounts, merchants, or categories in plaintext
- Recovery key material or vault seed

The server stores only:
- `blind_index` (keyed hash of record ID, for deduplication)
- `sealed` (NaCl sealed-box ciphertext, bucket-padded)
- Passkey public keys (for WebAuthn)
- Audit event metadata
- Encrypted recovery blob (ciphertext only)

## What the server CAN see

**The threat model must acknowledge:**

1. **Authentication metadata:** Passkey ceremony data, session tokens, CSRF tokens, login timestamps, IP-derived client references.

2. **Ciphertext metadata:** Number of records, ciphertext sizes (now bucketed), upload timestamps, blind index values (deterministic per record ID). These can leak usage patterns.

3. **JavaScript delivery:** The server delivers the browser JavaScript that performs encryption. A fully compromised origin or deploy pipeline can still replace the crypto code. Layered mitigations exist (SRI attributes, integrity manifest, CI smoke-test hash checks, out-of-band verification instructions). These raise the bar for accidental or partial tampering but do not defeat a simultaneous compromise of the git repo and the CI pipeline. See `docs/JS_INTEGRITY.md`.

4. **Timing and behavior:** When you sync, how often, from which IP (if opt-in logging is enabled), which endpoints you hit.

## Provider trust (SimpleFin and banks)

**SimpleFin and your bank can see your financial data.** This is unavoidable:
- SimpleFin is the intermediary that provides the bank feed. They see the transactions they relay.
- Your bank obviously knows your transactions.
- The SimpleFin access URL is a bearer credential. Anyone with the URL can fetch your transactions.

Mindful Money does not reduce the trust you place in SimpleFin or your bank. It only ensures that *the Mindful Money server* (Flask + Postgres) does not see your financial plaintext.

## KDF and offline attack resistance

New vaults use Argon2id with elevated parameters (v3; a v3 vault never falls back to weaker parameters, see `docs/THREAT_MODEL.md` risk register) (see `docs/OFFLINE_ATTACK_COST.md` for current version table and cost estimates). Legacy vaults retain prior parameters until the user upgrades. A 60-bit minimum passphrase entropy floor is enforced for new vaults. Weak passphrases still dominate residual risk.

Sealed records are padded to fixed bucket sizes, closing the prior merchant-name length side-channel.

## Recovery

An optional recovery key (256-bit, 32-word mnemonic) encrypts the vault seed. The server stores only the ciphertext. Automatic re-encryption of existing records under a new passphrase is implemented. See `docs/RECOVERY.md` for the exact steps and remaining limitations (single point of failure, no threshold, passkey still required for blob fetch, no hardware binding).

## ZKP limitations

A v3 circuit binds the validated plaintext to the stored ciphertext via a Poseidon2-based AEAD (ciphertext is a public circuit output). The prior v2 gap (proof of A, ciphertext of B) is closed for records that use the v3 path. v2 remains for backward compatibility. See `docs/ZKP_BINDING.md`.

ZKP verification requires the `bb` binary and verification key. The current production image omits both, so server-side ZKP verification is unavailable (fails closed with 503). Residual risk: `docs/THREAT_MODEL.md` risk register, "ZKP verifier absent in production".

## What "zero-knowledge" means here (and doesn't)

**Accurate claim:** "The Mindful Money server never sees your financial data in plaintext. All encryption happens in your browser before upload."

**Inaccurate claims to avoid:**
- "Zero-knowledge" (without qualification) — the JS delivery trust issue remains the dominant residual risk.
- "The server cannot identify you" — it sees auth metadata, IPs (if enabled), and usage patterns.
- "End-to-end encrypted" — SimpleFin and the bank see plaintext; only the Mindful Money server is excluded.
- "Compliance-ready" — no SOC 2, no HIPAA assessment, no formal security audit.

## Summary of trust assumptions

You must trust:
1. **Your browser** — not compromised, runs the served JavaScript faithfully
2. **The deployment pipeline and git repo** — the integrity checks catch some classes of tampering but not a full compromise of both
3. **SimpleFin** — with your transaction data
4. **Your bank** — with your transaction data
5. **Neon (Postgres)** — with ciphertext (cannot read it, but could delete it)
6. **Google Cloud** — with infrastructure (cannot read ciphertext, sees metadata)

You do NOT need to trust:
- The Mindful Money Flask server with your financial plaintext (it never sees it)
- Other users of the app (tenant isolation via identity_id)

## Recommendations before public claims

1. Do not use "zero-knowledge" in marketing without the qualifiers above.
2. Do not claim compliance with any framework (SOC 2, HIPAA, PCI DSS, etc.).
3. Obtain an independent security review before handling real financial data.
4. Treat the JS integrity mechanisms as raising the bar, not as a complete solution to origin compromise.
5. Prefer high-entropy passphrases; the recovery key does not excuse weak ones.

## Session security

Session cookies use:
- `HttpOnly`: True
- `SameSite`: Strict
- `Secure`: True in production
- `__Host-` prefix in production (`__Host-vault_session`)
- Custom server-side session storage
- Session rotation on privilege changes

Sessions are stored in the `server_sessions` table with hashed session IDs, idle and absolute timeouts, and revocation support.

## Content Security Policy

The app enforces a strict CSP:
- `default-src 'none'`
- `script-src 'self' 'wasm-unsafe-eval'`
- `connect-src 'self' https:`
- `style-src 'self'`
- `img-src 'self' data:`
- `frame-ancestors 'none'`
- `form-action 'self'`

No `unsafe-inline` or `unsafe-eval`. All JavaScript is served from `/static/`.

`connect-src` allows any `https:` host (for the SimpleFin bridge), so CSP does not restrict exfiltration destinations. Residual risk: `docs/THREAT_MODEL.md` risk register, "CSP `connect-src 'self' https:`".

## Frontend security

User data rendered via `innerHTML` is escaped with `escapeHtml()`. No `eval()` usage. CSP blocks inline scripts.
