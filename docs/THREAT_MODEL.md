# Threat Model

**Date:** 2026-10-12
**Scope:** Mindful Money personal finance tracker (single-user, Cloud Run + Neon)
**Method:** Adversarial review of code on main. Honesty is mandatory.

## Assets

| Asset | Location | Protection |
|-------|----------|------------|
| Financial transaction plaintext | Browser only | Argon2id-derived NaCl sealed boxes; never sent to server |
| Vault passphrase | User memory only | Never stored, never transmitted |
| Derived encryption keys | Browser memory (session) | Wiped on lock |
| Vault seed | Browser memory; encrypted backup via recovery key | 256-bit, Argon2id-wrapped |
| Recovery key (32-word mnemonic) | User storage (paper/password manager) | Never stored digitally by the app |
| SimpleFin access URL | Browser localStorage | Bearer credential; server never sees it |
| Passkey credentials | Browser + server (public key only) | WebAuthn; private key in authenticator |
| Ciphertext (`sealed` column) | Neon Postgres | Bucket-padded NaCl sealed boxes |
| Blind indexes | Neon Postgres | HMAC-SHA256 keyed hashes (deduplication only) |
| Audit metadata | Neon Postgres | Timestamps, event types, no plaintext |

## Actors

| Actor | Capability | Interest |
|-------|-----------|----------|
| **Compromised origin** | Replace served JavaScript | **DOMINANT RISK.** Can exfiltrate passphrase, keys, plaintext on next unlock. |
| **Malicious deploy pipeline** | Inject code via CI/CD | Same as compromised origin if both repo and CI are controlled. |
| **Neon operator** | Read/delete ciphertext | Cannot decrypt (no keys). Could delete or deny access. |
| **Google Cloud operator** | Infrastructure access | Sees metadata, not plaintext. Could disrupt service. |
| **Network attacker** | MITM (if TLS fails) | TLS 1.2+ required; HSTS enforced. Limited without cert compromise. |
| **SimpleFin** | Sees bank transactions | By design; user trusts SimpleFin with financial data. |
| **Bank** | Sees own transactions | By design. |
| **Thief (device)** | Physical access to unlocked device | Session timeouts and lock mitigate; unlocked browser = full access. |
| **Thief (recovery key)** | Finds 32-word mnemonic | Can decrypt vault seed backup; still needs passkey for blob fetch. |
| **Other app users** | Normal API access | Tenant isolation by `identity_id`; cannot access others' records. |

## Dominant residual risk

**A fully compromised origin or deploy pipeline can replace the served JavaScript and exfiltrate the passphrase or plaintext.**

This is architectural, not a bug. The browser must trust the server to deliver correct crypto code. All other controls are secondary to this trust.

**Why existing controls do not eliminate it:**

| Control | What it catches | What it misses |
|---------|----------------|----------------|
| SRI attributes (`integrity="sha384-..."`) | Detects if HTML references JS with wrong hash (accidental mismatch) | Attacker who controls the origin rewrites both HTML and JS; SRI is same-origin theater against a full compromise |
| `integrity-manifest.json` | Documents expected hashes for out-of-band verification | Same as above; manifest is served from the same origin |
| CI smoke-test hash check | Detects stale deploys, build corruption, partial tampering | Does not detect simultaneous compromise of git repo AND CI pipeline (attacker updates both code and manifest) |
| Out-of-band verification docs | Lets a paranoid user manually verify hashes | Requires user diligence on every load; not a scalable control |
| CSP (`script-src 'self'`) | Blocks inline scripts and external script injection | Does not block the origin itself from serving malicious `self` scripts |

**First-load trust is inherent.** There is no trust anchor outside the origin. This cannot be fixed without an out-of-band distribution mechanism (browser extension, signed package, etc.), which is out of scope for this project.

## Risk register

| Risk | Likelihood | Impact | Controls (reduce, not eliminate) | Residual |
|------|-----------|--------|----------------------------------|----------|
| Origin compromise → JS replacement → key exfiltration | Low (requires server or pipeline breach) | Catastrophic (full plaintext + passphrase) | SRI, manifest, CI checks, audit logging | **ACCEPTED. Dominant risk.** |
| Weak passphrase → offline brute force | Medium (user behavior) | High (full vault decryption) | 60-bit entropy floor for new vaults, Argon2id v3 (5 ops, 256MB) | Reduced for new vaults; legacy vaults retain weaker params |
| Recovery key theft | Low (physical/paper) | High (seed decryption) | Key is 256-bit; blob fetch requires passkey auth | Single point of failure; no threshold scheme |
| Session hijacking | Low | Medium (API access, not plaintext) | `__Host-` prefix, HttpOnly, SameSite=Strict, server-side sessions, rotation | Session token theft via XSS is mitigated by CSP; no XSS found |
| Database breach (Neon) | Low | Low (ciphertext only) | Bucket padding, sealed boxes, no plaintext at rest | Metadata leakage (record count, sizes, timestamps) |
| SimpleFin credential theft | Medium (localStorage) | High (bank transaction access) | Server never sees URL; user responsible for device security | Bearer credential; anyone with the URL can fetch transactions |
| Passkey phishing | Very low (WebAuthn) | Medium (account access, not plaintext) | WebAuthn origin binding | Cannot decrypt vault without passphrase |
| Insider (developer) | Low (single operator) | Catastrophic (could ship malicious JS) | Git history, CI checks | **Same as origin compromise; must be accepted** |

## What the operator must accept

Before storing real financial data, the operator must explicitly accept:

1. **Origin compromise = total compromise.** No technical control in this codebase prevents a compromised server from serving malicious JavaScript that captures the passphrase.

2. **No independent audit.** The cryptography has not been professionally reviewed.

3. **Recovery key is a single point of failure.** Lose both passphrase and mnemonic = permanent data loss.

4. **SimpleFin and the bank see plaintext.** This is by design, not a flaw.

5. **Infrastructure providers (Neon, Google Cloud) can delete or deny access to ciphertext.** They cannot decrypt it.

---

*This threat model is a living document. Update it when the architecture changes or new risks are identified.*
