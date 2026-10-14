# OWASP ASVS 5.0 mapping

**Framework:** OWASP Application Security Verification Standard 5.0.0
(release tag `v5.0.0_release`, files under `5.0/en/` in
<https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en>). Every
requirement ID below was checked against that source on 2026-10-13; the
text is paraphrased, the level (L1 to L3) is the one the standard assigns.

**Date:** 2026-10-13. **Scope:** the production deployment on Cloud Run
(`mindful-money-k23ukkh5cq-uc.a.run.app`), `main` at `dee30a5`.

**Status labels** (cumulative, strongest that applies):
implemented / locally tested / CI-verified / prod-verified / reviewed (an
independent reviewer checked it) / not done. "Partial" means part of the
requirement is met; the gap is stated. Nothing here has been independently
reviewed yet; see [HARDENING_PROPOSALS.md](HARDENING_PROPOSALS.md#r5-focused-external-code-review).

This is a selection of the chapters relevant to a browser-encrypted vault
with passkeys (V3, V6, V7, V8, V11, V13, V14, V15, V16). V5 (file
handling), V9 (self-contained tokens), V10 (OAuth/OIDC) and V17 (WebRTC)
do not apply: the app has no uploads to the server, no JWTs, no federated
login and no WebRTC. A full chapter-by-chapter pass is item
[R6](HARDENING_PROPOSALS.md#r6-versioned-security-verification-report).

Residual risks are stated once in their primary doc and only linked here:
origin compromise in [THREAT_MODEL.md](THREAT_MODEL.md#dominant-residual-risk),
server-visible metadata in [TRUST_BOUNDARIES.md](TRUST_BOUNDARIES.md#what-the-server-can-see).

## V3 Web Frontend Security

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 3.2.2 | L1 | Text rendered with safe functions, not as HTML | partial, CI-verified | Rendering uses `innerHTML` with `escapeHtml()` for every data field; browser tests store an HTML payload as a merchant and check it renders inert. Not `textContent` everywhere | medium |
| 3.3.1 | L1 | Cookies `Secure` and `__Host-`/`__Secure-` prefix | prod-verified | `__Host-vault_session; Secure` in production response headers (2026-10-13) | high |
| 3.3.2 | L2 | `SameSite` set per purpose | prod-verified | `SameSite=Strict` | high |
| 3.3.4 | L2 | Session cookie `HttpOnly` | prod-verified | `HttpOnly` | high |
| 3.4.1 | L1 | HSTS on all responses, max-age at least 1 year | prod-verified | `max-age=31536000; includeSubDomains` | high |
| 3.4.3 | L2 | CSP limits what the browser loads and executes | prod-verified, partial | `script-src 'self' 'wasm-unsafe-eval'`, `default-src 'none'`; `connect-src 'self' https:` is broad (risk in [THREAT_MODEL.md](THREAT_MODEL.md#risk-register); plan [R7](HARDENING_PROPOSALS.md#r7-restrict-unnecessary-browser-network-destinations)) | high |
| 3.4.4 | L2 | `X-Content-Type-Options: nosniff` | prod-verified | response headers | high |
| 3.4.5 | L2 | Referrer policy set | prod-verified | `Referrer-Policy: no-referrer` | high |
| 3.4.6 | L2 | CSP `frame-ancestors` on every response | prod-verified | `frame-ancestors 'none'` | high |
| 3.4.7 | L3 | CSP violation reporting location | not done | no `report-to`/`report-uri` | high |
| 3.4.8 | L3 | COOP `same-origin` on documents | prod-verified | `Cross-Origin-Opener-Policy: same-origin` | high |
| 3.5.3 | L1 | Sensitive functions use non-safe methods | CI-verified | state changes are POST/PUT/DELETE with CSRF token and Origin check (`test_demo.py`) | high |
| 3.6.1 | L3 | External assets only with SRI | implemented | no external assets; all JS vendored and same-origin, with SRI attributes anyway ([JS_INTEGRITY.md](JS_INTEGRITY.md)) | high |

## V6 Authentication

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 6.1.1 | L1 | Documented anti-automation and brute-force controls | implemented | rate limits and lockout documented in README "Ciphertext and resource limits" and `docs/THREAT_MODEL.md` | medium |
| 6.3.1 | L1 | Brute-force controls implemented as documented | CI-verified | Postgres rate limiter, `_is_account_locked` (5 failures in 15 min); tests in `test_demo.py`, `test_kdf_migrate_and_limits.py` | high |
| 6.3.3 | L2 | MFA or combined factors; L3 needs hardware-based factor | prod-verified (L2) | passkey (WebAuthn, user verification required) plus vault passphrase; production policy `VAULT_AUTH_POLICY=required` | high |
| 6.4.1 | L1 | Initial activation codes random, short-lived, single-use | partial | the bootstrap token is operator-generated; removal after first enrollment is pending ([BOOTSTRAP_TOKEN.md](BOOTSTRAP_TOKEN.md)); bootstrap is refused once a passkey exists | medium |
| 6.5.6 | L3 | Any factor revocable on loss | CI-verified | passkeys can be removed (step-up gated); browser test covers add, rename, remove | high |
| 6.7.2 | L3 | Challenge nonce at least 64 bits, unique | implemented | WebAuthn challenges from `secrets` (32 bytes), single-use (`_take_challenge`) | high |

## V7 Session Management

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 7.1.1 | L2 | Inactivity and absolute timeouts documented | implemented | `SESSION_IDLE_TTL` 900 s, `SESSION_TTL` 4 h (`app.py`), README | high |
| 7.2.1 | L1 | Session verification in a trusted backend | prod-verified | server-side sessions in Postgres keyed by a hash of the cookie | high |
| 7.2.3 | L1 | Reference tokens from a CSPRNG, at least 128 bits | implemented | `secrets.token_urlsafe(32)` | high |
| 7.2.4 | L1 | New session token on (re)authentication | CI-verified | `_rotate_session` on passkey login and step-up; browser test checks CSRF rotation | high |
| 7.3.1 | L2 | Inactivity timeout enforced | CI-verified | idle check in `open_session` | high |
| 7.3.2 | L2 | Absolute maximum lifetime enforced | prod-verified | cookie `Max-Age=14400`, server `expires_at` | high |
| 7.4.1 | L1 | Terminated sessions cannot be reused | CI-verified | logout and rotation set `revoked_at`; revoked sessions refused | high |
| 7.4.3 | L2 | Option to end other sessions after an authentication change | partial | a rekey (recovery) revokes all other sessions; passkey changes do not offer it | medium |
| 7.4.4 | L2 | Visible logout on authenticated pages | implemented | Sign out and Lock vault buttons | high |
| 7.5.3 | L3 | Extra authentication for highly sensitive operations | CI-verified | recent passkey assertion (300 s) for delete-all, recovery blob, rekey | high |

## V8 Authorization

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 8.2.2 | L1 | Data-specific access restricted (no IDOR) | CI-verified | every query scoped to `current_identity_id()`; cross-identity tests in `test_demo.py`, `test_recovery_rekey.py` | high |
| 8.3.1 | L1 | Authorization enforced server-side | CI-verified | `require_access()` and step-up checks in `app.py` | high |
| 8.4.1 | L2 | Cross-tenant controls in multi-tenant apps | CI-verified | identity scoping on records, rekeys, audit events | high |

## V11 Cryptography

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 11.1.2 | L2 | Cryptographic inventory | partial | primitives listed across `TRUST_BOUNDARIES.md`, `RECOVERY.md`, `OFFLINE_ATTACK_COST.md`; no single inventory (part of [R6](HARDENING_PROPOSALS.md#r6-versioned-security-verification-report)) | high |
| 11.2.1 | L2 | Industry-validated crypto implementations | implemented | libsodium (vendored `libsodium-wrappers`, pinned by SRI) for sealing, Argon2id, BLAKE2b. The optional ZKP path uses Poseidon2 via Noir and Barretenberg, which is not a standard AEAD and is unreviewed ([ZKP_BINDING.md](ZKP_BINDING.md)) | medium |
| 11.2.3 | L2 | At least 128-bit security | implemented | X25519 sealed boxes (about 128-bit), 256-bit keys | high |
| 11.3.3 | L2 | Authenticated encryption against modification | CI-verified | NaCl sealed box (XSalsa20-Poly1305); tamper tests in `test_demo.py` | high |
| 11.3.2 | L1 | Only approved ciphers and modes | needs review | XSalsa20-Poly1305 is not AES-GCM; whether it counts as "approved" per ASVS Appendix C needs an assessor's call | low |
| 11.4.4 | L2 | Approved KDF with stretching for password-derived keys | CI-verified | Argon2id v3 (5 ops, 256 MB), no fallback (`tests/kdf_no_fallback.test.mjs`) | high |
| 11.5.1 | L2 | CSPRNG, at least 128 bits for non-guessable values | implemented | `crypto.getRandomValues`/libsodium in the browser, `secrets` on the server | high |
| 11.7.1 | L3 | Full memory encryption | not done | not available to a browser app; partial zeroization only ([R3](HARDENING_PROPOSALS.md#r3-explicit-zeroization-and-automatic-vault-locking)) | high |

## V13 Configuration

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 13.1.1 | L2 | All communication needs documented | partial | Neon, SimpleFin (browser-side) documented in `TRUST_BOUNDARIES.md`; no single list ([R7](HARDENING_PROPOSALS.md#r7-restrict-unnecessary-browser-network-destinations)) | medium |
| 13.3.1 | L2 | Secrets in a secrets manager | prod-verified | `VAULT_SECRET_KEY`, `VAULT_DATABASE_URL` from Secret Manager (`deploy.yml`) | high |
| 13.3.2 | L2 | Least-privilege access to secrets | not done | not audited ([R2](HARDENING_PROPOSALS.md#r2-github-and-cloud-run-deployment-authorization-hardening)) | low |
| 13.4.1 | L1 | No source control metadata deployed | implemented | Dockerfile copies named files and directories only | high |
| 13.4.2 | L2 | Debug modes off in production | implemented | Gunicorn, `debug=False`; dev server refuses `PRODUCTION` | high |

## V14 Data Protection

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 14.2.1 | L1 | No sensitive data in URLs | implemented | secrets travel in bodies or cookies; the SimpleFin access URL stays in the browser | medium |
| 14.2.3 | L2 | No sensitive data to untrusted parties | implemented | no trackers or third-party scripts; plaintext never leaves the browser except to the user-chosen SimpleFin bridge request | medium |
| 14.3.1 | L1 | Client data cleared after session ends | partial | `lockVault()` clears keys and transactions; no idle auto-lock ([R3](HARDENING_PROPOSALS.md#r3-explicit-zeroization-and-automatic-vault-locking)) | medium |
| 14.3.2 | L2 | Anti-caching headers | prod-verified | `Cache-Control: no-store` | high |
| 14.3.3 | L2 | No sensitive data in browser storage | implemented | localStorage holds only an optional display name and legacy non-secret salts | medium |

## V15 Secure Coding and Architecture

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 15.1.1 | L1 | Documented remediation time frames for vulnerable dependencies | not done | `pip-audit` blocks on production dependencies in CI; no written time frames | high |
| 15.1.2 | L2 | SBOM or inventory of third-party components | partial | hashed `requirements-hashed.txt`, vendored JS pinned in the integrity manifest; no SBOM | medium |
| 15.2.2 | L2 | Defenses against resource-heavy functionality | CI-verified | request size, batch and per-tenant limits, rate limits (`test_kdf_migrate_and_limits.py`) | high |
| 15.3.4 | L2 | Client IP from trusted proxy data only | implemented | `VAULT_TRUST_PROXY=1` with ProxyFix on Cloud Run | medium |

## V16 Security Logging and Error Handling

| ID | Lvl | Requirement (short) | Status | Evidence | Conf. |
|---|---|---|---|---|---|
| 16.2.5 | L2 | Logging follows data protection levels | CI-verified | DB error redaction (`test_db_error_logging.py`), HMAC client refs, IP logging opt-in ([LOGGING.md](LOGGING.md)) | high |
| 16.3.1 | L2 | All authentication operations logged | implemented | passkey success/failure audit events | medium |
| 16.4.3 | L2 | Logs shipped to a separate system | prod-verified | Cloud Logging (separate from the app and DB) | medium |
| 16.5.1 | L2 | Generic error messages | CI-verified | `api_error` bodies; 503 handler returns a generic body (P1) | high |

## Gaps summary

Not done or partial, each with its plan: 3.4.7 (CSP reporting), 6.4.1
(bootstrap token removal, P4), 7.4.3 (end other sessions after passkey
changes), 11.1.2 and 15.1.1 (inventory and remediation policy, R6),
11.3.2 (needs an assessor's view of XSalsa20-Poly1305), 11.7.1 and 14.3.1
(R3), 13.1.1 and 3.4.3 (R7), 13.3.2 (R2), 15.1.2 (SBOM, R6).
