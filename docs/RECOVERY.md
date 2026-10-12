# Recovery Key Mechanism

## Overview

The recovery key is a 256-bit random value, encoded as 32 English words,
that encrypts the vault seed. It provides a way to regain access if the
passphrase is forgotten.

## Security properties

- **Server never sees the key:** The client generates the key, encrypts the
  seed locally, and sends only the ciphertext (blob) to the server.
- **Independent of passphrase:** The recovery key is randomly generated,
  not derived from the passphrase. A weak passphrase does not weaken the
  recovery key, and a strong recovery key does not excuse a weak passphrase.
- **One-time display:** The mnemonic is shown once. The user must write it
  down on paper. It is never stored digitally by the app.
- **Passkey-gated access:** Retrieving the encrypted blob requires fresh
  passkey authentication (not just a session cookie).

## Threat model

**What it protects against:**
- Forgotten passphrase (user error)
- The recovery key is 256 bits; brute force is infeasible

**What it does NOT protect against:**
- Someone who finds the paper copy (physical security is the user's responsibility)
- A compromised server that serves malicious JS (see docs/JS_INTEGRITY.md)
- The user storing the mnemonic digitally (screenshots, cloud notes, etc.)

## UX design (anti-weak-passphrase)

The recovery flow explicitly does NOT encourage weak passphrases:

1. During setup, the UI states: "A recovery key does not make a weak
   passphrase safe; choose a strong passphrase anyway."
2. During recovery, the new passphrase must still meet the 60-bit entropy
   minimum. The recovery key cannot be used to set a weak passphrase.
3. The recovery key is presented as a last resort, not a primary method.

## Wordlist

Current: 256-word list, 32 words per key (8 bits/word).
Production should use BIP-39 (2048 words, 24 words with checksum).

The wordlist is in `static/recovery-words.js`.

## API

- `POST /api/recovery/setup` - Store encrypted blob (requires auth)
- `GET /api/recovery/blob` - Retrieve blob (requires passkey auth)
- `POST /api/recovery/delete` - Delete blob (requires passkey auth)

## Limitations and future work

- **Re-encryption flow incomplete:** Currently, recovery decrypts the seed
  but does not automatically re-encrypt existing records with a new
  passphrase. The user must manually export/import. A full implementation
  would: decrypt all records with old seed-derived keys, generate new
  salts, derive new keys from new passphrase, re-encrypt all records.
- **No threshold scheme:** A single recovery key is a single point of
  failure (if lost) and a single point of compromise (if found). Future
  work could implement Shamir's Secret Sharing (e.g., 2-of-3).
- **No hardware binding:** The recovery key is not bound to a hardware
  token. A future enhancement could require both the mnemonic AND a
  passkey to complete recovery.
