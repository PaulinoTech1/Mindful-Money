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
- **Passkey-gated access:** Retrieving the encrypted blob requires a recent
  passkey assertion (not just a session cookie); see API below.

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

- `POST /api/recovery/setup` - Store encrypted blob (signed-in session).
- `GET /api/recovery/status` - `{"set_up": bool}` only (signed-in session).
- `GET /api/recovery/blob` - Retrieve blob. Gate: a registered passkey, a
  passkey-authenticated session, and a WebAuthn assertion within
  `VAULT_STEPUP_WINDOW_SECONDS` (default 300 s). Same gate as deleting all
  records. A user who forgot the passphrase can still pass it with the
  passkey; the browser runs the passkey ceremony on 401 and retries once.
- `POST /api/recovery/delete` - Delete blob. Same gate.
- `POST /api/vault/rekey/begin`, `/records`, `/commit`, `/abort` - atomic
  re-encryption, see "Re-encryption (rekey)".

Before 2026-10-13 the blob fetch and delete checked a session flag
(`passkey_authenticated`) that nothing set and the server-side session store
could not hold, so recovery always failed with 403 (bug L).

## Exact recovery steps (updated 2026-10-13)

If you forget your passphrase but have the 32-word recovery key:

1. Sign in with your passkey. On the locked passphrase gate click "Forgot
   passphrase? Use recovery key" (when unlocked, the Recovery card has
   "Recover vault with key").
2. Enter all 32 recovery words (in order, separated by spaces).
3. Enter a NEW passphrase (must meet the 60-bit entropy minimum).
4. Confirm the re-encryption prompt. If your passkey sign-in is older than
   5 minutes, the browser asks for your passkey again.
5. The app re-encrypts the vault as described below and returns to the
   locked gate.
6. Unlock with the new passphrase. All records are preserved and the same
   recovery key keeps working.

## Re-encryption (rekey)

This is the primary description of the design; other docs link here.

Recovering with a new passphrase changes every key: the seed (and so the
keypair) and the index key are derived from the passphrase and new salts.
Every record must be re-sealed and its blind index recomputed, because the
blind index is BLAKE2b(record id) keyed with the index key.

Steps (all crypto in the browser):

1. Decode the 32 words to the recovery key; fetch the blob (gate above);
   unwrap the OLD seed; derive the OLD keypair.
2. `POST /api/vault/rekey/begin` (same recent-passkey gate). The server
   records a snapshot of the live record set (count and a SHA-256 over
   blind indexes and ciphertext hashes) and returns a `rekey_id`. A newer
   begin replaces an unfinished one. While a rekey is active (TTL
   `VAULT_REKEY_TTL_SECONDS`, default 600 s), normal record writes and
   delete-all return 409.
3. Fetch every record (paginated), decrypt with the old keypair, generate
   two fresh random 16-byte salts in the browser, derive the new keys with
   KDF v3, re-seal every record and recompute its blind index under the NEW
   index key. A record that does not decrypt or has no id aborts the whole
   rekey; nothing is dropped.
4. Upload the staged records to `POST /api/vault/rekey/records` as
   `{blind_index, old_blind_index, sealed}`, chunked by the same 500-record
   and 6 MiB limits as normal uploads (worst case 500 x 16658 + wrapper
   = about 8,329,060 bytes, under the 8 MiB request limit; asserted in
   `test_recovery_rekey.py`). Staging is a separate table
   (`vault_rekey_records`), so old and new blind indexes never meet the
   `records` unique constraint.
5. Wrap the NEW seed with the SAME recovery key and `POST
   /api/vault/rekey/commit` with the new salts, KDF version and blob. In one
   transaction, holding the identity row lock, the server checks the rekey
   is live and owned, the live set still matches the snapshot, and the
   staged set replaces every live record exactly once (via
   `old_blind_index`); then deletes the old records, inserts the staged
   ones (public ZK commitments follow their record), writes the salts,
   version and blob, deletes the rekey, and revokes every other session of
   the vault. Any failure rolls the whole transaction back.
6. The browser wipes old and new key material and returns to the locked
   gate. The user unlocks with the new passphrase. No automatic unlock.

Decisions:

- **The recovery key keeps working.** The commit stores the new seed wrapped
  with the same recovery key, so the paper copy stays valid. Rejected:
  rotating the key on every recovery (the user would have to write down a
  new 32-word key at the moment they are already recovering, and a missed
  write-down leaves no recovery path). Users who want a new key can delete
  and regenerate it.
- **Other sessions are revoked at commit.** Other tabs still hold the old
  keys in memory; anything they wrote afterwards would be unreadable under
  the new keys. Record writes take a shared lock on the identity row and
  re-check that their session is not revoked, so a write cannot slip in
  after the commit from a revoked session.
- **Crash safety.** Nothing live changes before commit. If the browser dies
  mid-rekey, the old vault (records, salts, recovery blob) is intact and
  unlocks with the old passphrase, or can be recovered again with the
  recovery key. On any client error the browser calls
  `/api/vault/rekey/abort` at once. If it could not (tab closed, crash),
  the next unlock in any tab of the vault aborts it; otherwise writes stay
  blocked until the TTL (10 minutes) or a new begin. Abort takes the
  identity row lock FOR UPDATE like commit, so it waits for a commit in
  progress and can never interleave with one.
- **TTL 600 s.** It must cover a slow rekey: KDF v3 (256 MB) on a phone
  takes up to about 30 s, re-sealing a 20 MB decade of records a few
  seconds, and uploading 20 MB on a 1 Mbit/s mobile uplink about 160 s,
  so about 200 s worst case; 600 s keeps a 3x margin. A shorter TTL would
  turn a slow but healthy recovery into a 404 at commit (safe, but the user
  must start over). Trade-off: unlocking in a second tab while a recovery
  is running in another aborts that recovery; its commit then returns 404
  and the vault is unchanged.
- **Rate limits.** begin/commit/abort: 10 per hour; blob fetch and delete:
  20 per hour; staging chunks count against the normal upload limit
  (60 per minute; README "Ciphertext and resource limits").
- **What the server learns.** The mapping from old to new blind index for
  each record (it could infer this anyway from counts and timing), the new
  salts (not secret, as before) and a new opaque blob. Never the recovery
  key, seed, passphrase or plaintext.

Rejected approaches: upserting re-encrypted records in place (the old
code; keeps old blind indexes, so later syncs duplicate every record, and
a crash leaves a mix of old and new keys); delete-all then upload (data
loss window); a key "generation" column on `records` with a flip (touches
every query and the unique constraint for no extra safety over a staging
table).

## Limitations and future work

- **No threshold scheme:** A single recovery key is a single point of
  failure (if lost) and a single point of compromise (if found). Future
  work could implement Shamir's Secret Sharing (e.g., 2-of-3).
- **No hardware binding:** The recovery key is not bound to a hardware
  token. Using it already requires a recent passkey assertion (blob gate),
  but the key itself is not cryptographically tied to the passkey.
- **Recovery does not revoke the recovery key:** because it keeps working
  after a recovery (decision above), a recovery key that may have been seen
  by someone else must be deleted and regenerated explicitly.
- **Recovery requires passkey auth:** Fetching the encrypted blob requires
  fresh WebAuthn authentication. If you lose both your passphrase AND
  your passkey, recovery is impossible. Store them separately.
