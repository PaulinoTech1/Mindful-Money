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

## Exact recovery steps (as of 2026-10-12)

If you forget your passphrase but have the 32-word recovery key:

1. Go to the Security section, click "Recover vault with key"
2. Enter all 32 recovery words (in order, separated by spaces)
3. Enter a NEW passphrase (must meet 60-bit entropy minimum)
4. Confirm the re-encryption prompt
5. The app will:
   a. Decode the mnemonic to the 256-bit recovery key
   b. Fetch the encrypted blob from `/api/recovery/blob` (requires passkey auth)
   c. Decrypt the blob to recover the OLD vault seed
   d. Reconstruct the OLD keypair from the seed
   e. Download all encrypted records
   f. Decrypt each record with the OLD private key
   g. Generate NEW salts (new vault identity)
   h. Derive NEW keys from the new passphrase (Argon2id v3)
   i. Re-encrypt each record with the NEW public key (with bucket padding)
   j. Upload re-encrypted records (upsert by blind_index replaces old ciphertext)
   k. Clear all old key material from memory
6. Your vault is now accessible with the new passphrase. All records are preserved.

**What happens to the old data:**
- Old ciphertext is replaced on the server (upsert by blind_index)
- The old seed is wiped from browser memory
- You should generate a NEW recovery key after recovery (the old one still
  decrypts the old seed, which is now useless, but good hygiene)

## Limitations and future work

- **No threshold scheme:** A single recovery key is a single point of
  failure (if lost) and a single point of compromise (if found). Future
  work could implement Shamir's Secret Sharing (e.g., 2-of-3).
- **No hardware binding:** The recovery key is not bound to a hardware
  token. A future enhancement could require both the mnemonic AND a
  passkey to complete recovery.
- **Recovery requires passkey auth:** Fetching the encrypted blob requires
  fresh WebAuthn authentication. If you lose both your passphrase AND
  your passkey, recovery is impossible. Store them separately.
