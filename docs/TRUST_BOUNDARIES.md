# Trust Boundaries

**Last updated:** 2026-10-11
**Status:** Honest assessment, not marketing

This document states exactly what Mindful Money protects against and what it
does not. Do not describe the app as "zero-knowledge" without these qualifiers.

## What the server cannot see

The Flask backend never receives:
- Plaintext transaction data (encrypted in browser before upload)
- SimpleFin credentials or access URLs (handled entirely client-side)
- Vault passphrases or derived encryption keys
- Financial amounts, merchants, or categories in plaintext

The server stores only:
- `blind_index` (HMAC of record ID, for deduplication)
- `sealed` (NaCl sealed-box ciphertext)
- Passkey public keys (for WebAuthn)
- Audit event metadata

## What the server CAN see

**The threat model must acknowledge:**

1. **Authentication metadata:** Passkey ceremony data, session tokens, CSRF tokens,
   login timestamps, IP-derived client references.

2. **Ciphertext metadata:** Number of records, ciphertext sizes, upload timestamps,
   blind index values (deterministic per record ID). These can leak usage patterns.

3. **JavaScript delivery:** The server delivers the browser JavaScript that performs
   encryption. A compromised server (or compromised deployment pipeline) could serve
   malicious JavaScript that exfiltrates passphrases or plaintext before encryption.
   **The zero-knowledge guarantee depends entirely on the integrity of the served
   JavaScript.** There is no code signing, SRI, or reproducible build verification
   in the current deployment.

4. **Timing and behavior:** When you sync, how often, from which IP (if opt-in
   logging is enabled), which endpoints you hit.

## Provider trust (SimpleFin and banks)

**SimpleFin and your bank can see your financial data.** This is unavoidable:
- SimpleFin is the intermediary that provides the bank feed. They see the
  transactions they relay.
- Your bank obviously knows your transactions.
- The SimpleFin access URL is a bearer credential. Anyone with the URL can
  fetch your transactions.

Mindful Money does not reduce the trust you place in SimpleFin or your bank.
It only ensures that *the Mindful Money server* (Flask + Postgres) does not
see your financial plaintext.

## ZKP limitations

The Noir circuit for manual expense proofs has a critical limitation documented
in `zkp/README.md`:

> The proof establishes knowledge of a valid plaintext whose Poseidon2 hash is
> the public commitment. It does **not** establish that the separately submitted
> `sealed` ciphertext encrypts that same plaintext. A modified client can prove
> valid record A and submit ciphertext B.

Additionally:
- ZKP artifacts (verification key, `bb` binary) are not included in the production
  Cloud Run image. ZKP verification is disabled in production.
- The circuit does not prove ciphertext consistency. This is a fundamental
  limitation, not a bug.

## What "zero-knowledge" means here (and doesn't)

**Accurate claim:** "The Mindful Money server never sees your financial data in
plaintext. All encryption happens in your browser before upload."

**Inaccurate claims to avoid:**
- "Zero-knowledge" (without qualification) - implies stronger guarantees than
  provided, especially given the JavaScript delivery trust issue.
- "The server cannot identify you" - it sees auth metadata, IPs (if enabled),
  and usage patterns.
- "End-to-end encrypted" - SimpleFin and the bank see plaintext; only the
  Mindful Money server is excluded.
- "Compliance-ready" - no SOC 2, no HIPAA assessment, no formal security audit.

## Summary of trust assumptions

You must trust:
1. **Your browser** - not compromised, runs the served JavaScript faithfully
2. **The deployment pipeline** - GitHub Actions serves the correct JavaScript
3. **SimpleFin** - with your transaction data (they're the feed provider)
4. **Your bank** - with your transaction data (obviously)
5. **Neon (Postgres)** - with ciphertext (cannot read it, but could delete it)
6. **Google Cloud** - with infrastructure (cannot read ciphertext, sees metadata)

You do NOT need to trust:
- The Mindful Money Flask server with your financial plaintext (it never sees it)
- Other users of the app (tenant isolation via identity_id)

## Recommendations before public claims

1. Do not use "zero-knowledge" in marketing without the qualifiers above.
2. Do not claim compliance with any framework (SOC 2, HIPAA, PCI DSS, etc.).
3. Consider a formal security review before handling real financial data.
4. Consider code signing or SRI for the served JavaScript.
5. KDF salts are stored server-side per identity (migrated from legacy
   browser-local storage). Clearing browser data no longer loses access.
   Legacy vaults with localStorage salts can migrate via /api/kdf/salts/migrate.
   Backup files include salts for cross-device recovery.

## Session security

Session cookies use:
- `HttpOnly`: True (not accessible via JavaScript)
- `SameSite`: Strict (not sent on cross-site requests)
- `Secure`: True in production (HTTPS only)
- Custom server-side session storage (not Flask's default client-side sessions)
- Session rotation on privilege changes

Sessions are stored in the `server_sessions` table with:
- Hashed session IDs (SHA-256, not reversible)
- Idle timeout (15 minutes) and absolute timeout (4 hours)
- Revocation support via `/api/session/revoke`

**Note:** Cookie name is `vault_session` (not `__Host-` prefixed). The `__Host-`
prefix would provide additional protection against cookie tossing, but was not
used to avoid breaking existing sessions. Consider for a future migration.

## Content Security Policy

The app enforces a strict CSP:
- `default-src 'none'` - deny by default
- `script-src 'self' 'wasm-unsafe-eval'` - allows libsodium WASM, no inline scripts
- `connect-src 'self' https:` - allows SimpleFin bridge fetches (client-side)
- `style-src 'self'` - no inline styles
- `img-src 'self' data:` - allows data URIs for images
- `frame-ancestors 'none'` - no embedding
- `form-action 'self'` - forms only to self

The `wasm-unsafe-eval` is required for libsodium. There are no `unsafe-inline`
or `unsafe-eval` directives. All JavaScript is served from `/static/`.

## Frontend security

**XSS protection:**
- All user data rendered via `innerHTML` is escaped with `escapeHtml()`
- The `escapeHtml` function handles `& < > " '`
- No `eval()` usage
- CSP blocks inline scripts (`script-src 'self'`)

**Verified:** 2026-10-11 - `grep` for `eval(`, `innerHTML` shows proper escaping.
