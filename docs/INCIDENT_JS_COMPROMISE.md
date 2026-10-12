# Incident Response: Suspected JS/Origin Compromise

**Severity:** CRITICAL
**Date:** 2026-10-12

## When to use this

- CI integrity smoke test fails (served JS hash ≠ manifest)
- Manual verification shows served JS differs from committed code
- Unexpected network requests from the app to unknown hosts
- User reports passphrase prompt appearing at unusual times
- Any evidence that served JavaScript was modified

## Immediate actions (first 30 minutes)

1. **Do NOT enter your passphrase** into the app until the compromise is resolved.
2. **Revoke all sessions:** Delete from `server_sessions` table or use the admin endpoint.
3. **Take the service offline:** Set Cloud Run traffic to 0 or disable the service.
   ```bash
   gcloud run services update-traffic mindful-money \
     --region us-central1 --to-latest=0 \
     --project project-c89a7f58-b865-4112-bf8
   ```
4. **Preserve evidence:** Save the served JS files, HTTP logs, and deployment history before remediation.

## Critical fact: passphrase exposure

**If malicious JavaScript was served, assume all passphrases entered during the compromise window are exposed.**

Previously derived keys cannot be retroactively protected. An attacker who captured a passphrase can:
- Derive the same Argon2id keys offline
- Decrypt all ciphertext they also exfiltrated
- This remains true even after the malicious JS is removed

**Changing your passphrase after a compromise does NOT protect data that was already exfiltrated.** The attacker has the old passphrase and the old ciphertext.

## Recovery procedure

1. **Identify the compromise window:** From CI logs, determine when the malicious JS was first served and when it was removed.
2. **Assume breach for active users:** Anyone who unlocked their vault during the window must assume passphrase exposure.
3. **Rotate SimpleFin credentials:** The access URL may have been exfiltrated. Generate a new one via SimpleFin.
4. **For each affected user:**
   a. Use the recovery key to re-encrypt all records with a NEW passphrase (see `docs/RECOVERY.md`)
   b. Generate a NEW recovery key (the old mnemonic may be compromised)
   c. Re-enroll passkeys (the old WebAuthn credentials may still be valid, but rotate for hygiene)
5. **Do NOT simply change the passphrase** without re-encrypting. The old ciphertext + old passphrase = readable by the attacker.

## Detection signals

| Signal | Source | What it means |
|--------|--------|---------------|
| CI smoke test failure | `.github/workflows/deploy.yml` | Served JS hash ≠ committed manifest. Could be stale deploy OR tampering. |
| `/api/version` mismatch | Manual check | Deployed commit ≠ expected. Investigate. |
| Unexpected audit events | `audit_events` table | Look for `kdf_salts_generated`, `recovery_blob_fetched`, or `records_uploaded` at unusual times. |
| New admin sessions | `server_sessions` table | Sessions from unknown IPs or at unusual hours. |
| CSP violation reports | Browser console (if reporting enabled) | May indicate injected scripts. |

## What does NOT detect compromise

- `/health` returning 200 (malicious JS still serves a healthy endpoint)
- Uptime monitoring (only checks availability, not integrity)
- Database integrity checks (ciphertext is unchanged; the attack is in the JS layer)

## Post-incident

1. Determine root cause: git compromise? CI compromise? Cloud Run compromise?
2. Rotate all infrastructure credentials (GCP service accounts, Neon passwords, GitHub tokens)
3. Review `docs/THREAT_MODEL.md` and update if the attack vector was not previously considered
4. Consider whether the deployment pipeline needs additional controls

## Residual risk statement

This incident response plan assumes you DETECT the compromise. A sophisticated attacker who controls both the git repo and the CI pipeline can update the integrity manifest to match their malicious JS, defeating the smoke test. **Detection is not guaranteed.**
