# Security Audit Scope

**Purpose:** Focused cryptographic and application-security review suitable for a $2k–$5k freelance engagement (approximately 15–30 hours).

**Repository:** https://github.com/PaulinoTech1/Mindful-Money
**Date:** 2026-10-12

## In scope

### 1. Key derivation (Argon2id)

- **Files:** `static/app.js` (`deriveKeys`, `kdfParams`), `app.py` (`/api/kdf/salts/*`)
- **Questions:**
  - Are v1/v2/v3 parameters correctly implemented? (v3 = 5 ops, 256MB, Argon2id)
  - Is the 60-bit entropy estimator conservative or does it overestimate?
  - Can a weak passphrase bypass the new-vault gate (e.g., via salt pre-generation)?
  - Is the v3→v2 fallback safe, or does it silently downgrade security?
  - Are salts unique per identity and properly persisted?

### 2. Sealing and padding

- **Files:** `static/app.js` (`seal`, `unseal`, `padPlaintext`, `unpadPlaintext`)
- **Questions:**
  - Is `crypto_box_seal` used correctly (ephemeral keypair, nonce handling)?
  - Does bucket padding actually hide plaintext length? Are buckets sufficient?
  - Is unpadding safe against oracle attacks?
  - Are there length leaks in `blind_index` or other metadata?

### 3. Recovery path

- **Files:** `static/app.js` (`handleRecoverVault`, `recoverWithKey`), `app.py` (`/api/recovery/*`)
- **Questions:**
  - Is the 32-word mnemonic decoded safely? (No checksum; is this acceptable?)
  - Does re-encryption correctly replace all old ciphertext?
  - Are old keys wiped from memory after re-encryption?
  - Can an attacker trigger recovery to overwrite a victim's records?
  - Is the recovery blob properly authenticated?

### 4. WebAuthn and session handling

- **Files:** `app.py` (passkey endpoints, session management)
- **Questions:**
  - Is WebAuthn ceremony validation correct (origin, RP ID, challenge)?
  - Are session tokens cryptographically random and properly invalidated?
  - Does `__Host-` cookie prefix work as intended in production?
  - Is there a session fixation or revocation race condition?
  - Is step-up authentication enforced for destructive actions?

### 5. ZKP binding (v4)

- **Files:** `zkp/manual_expense_v4/src/main.nr`, `static/zkp/manual_expense_v4_core.js`, `static/zkp/manual_expense_v4_client.js`, `zkp_verifier.py`, ZKP endpoints in `app.py`
- **Questions:**
  - Does the circuit bind the key to the registered commitment, and the validated plaintext to the stored ciphertext?
  - Is the key schedule (`zk_root`, per-record key and nonce) sound, and does the commitment leak anything beyond the documented Argon2id-bound guessing oracle?
  - Is the Poseidon2 AEAD construction sound?
  - Can a prover substitute a different ciphertext than what was proven?
  - Are the proving/verification keys generated securely?

### 6. JS integrity controls and their limits

- **Files:** `static/integrity-manifest.json`, `scripts/generate_integrity.py`, `.github/workflows/deploy.yml` (smoke test)
- **Questions:**
  - Do the SRI hashes match the served files?
  - Does the CI smoke test actually fail on mismatch?
  - Are the documented limitations accurate? (We claim these do NOT defeat full origin compromise; verify this is true and complete.)
  - Is there a gap where an attacker could bypass the checks?

## Out of scope

The following are **architectural limitations**, not audit findings:

- **Full origin compromise:** If an attacker controls the server, they can serve malicious JavaScript. This is inherent to the web delivery model and cannot be fixed by code review. Documented in `docs/THREAT_MODEL.md`.
- **SimpleFin/bank plaintext:** By design, SimpleFin and the bank see transaction data. This is not a vulnerability.
- **Social engineering:** Phishing the user for their passphrase or recovery key is out of scope.
- **Infrastructure security:** Neon and Google Cloud configuration are out of scope (assume standard hardening).
- **Denial of service:** Availability attacks are out of scope.

## Deliverables expected

1. Written report with findings rated by severity (Critical/High/Medium/Low/Informational)
2. For each finding: affected file(s) and line(s), impact, and recommended fix
3. Explicit confirmation or correction of the documented residual risks
4. Opinion on whether the system is suitable for personal use with real financial data, with qualifications

## Residual risks the operator must still accept

Even after a clean audit, the operator must accept:

1. **Origin compromise = total compromise.** The audit cannot fix the trust-on-first-load problem.
2. **The audit is point-in-time.** Future code changes may introduce new vulnerabilities.
3. **No formal verification.** The audit is a human review, not a mathematical proof of correctness.
4. **User behavior.** Weak passphrases, lost recovery keys, and compromised devices are outside the audit's control.

## Budget guidance

- **$2k–$3k:** Focus on items 1–4 (KDF, sealing, recovery, WebAuthn/sessions). ~15 hours.
- **$3k–$5k:** Add items 5–6 (ZKP, JS integrity). ~25–30 hours.
- Look for auditors with: libsodium/NaCl experience, WebAuthn knowledge, and ideally Noir/Circom familiarity for the ZKP portion.
