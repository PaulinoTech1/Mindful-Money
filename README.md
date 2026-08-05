# Vault — working prototype

A privacy-first finance tracker where the server stores your transactions and
cannot read them. Fake bank data, real cryptography, charts computed entirely
in your browser.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
# open http://localhost:5000
```

## Authentication policy and passkey protection

`VAULT_AUTH_POLICY` is explicit: `optional` or `required`. Development defaults
to `optional` for the localhost prototype and optional mode may bind only to a
loopback host. Production has no optional default and refuses to start unless
`VAULT_AUTH_POLICY=required`. Required policy protects APIs independently of
whether a credential happens to have been enrolled; an existing deployment
must enroll its passkey before switching to required production policy.

Passkeys are optional. A new or existing installation continues in the current
passphrase-only mode until **Enable passkey protection** is chosen from inside
an unlocked vault. A passkey authenticates the Flask session and authorizes
access to stored ciphertext; it never derives or replaces the vault key. The
passphrase remains in the browser, runs through the unchanged Argon2id key
derivation, and decrypts records locally.

After protection is enabled, future access has two distinct steps:

1. **Sign in with passkey** to access the server's encrypted records.
2. **Unlock vault with passphrase** to derive the encryption key locally.

A passkey cannot recover a forgotten passphrase. Add a backup passkey from the
Security section before the primary device is lost. The final passkey cannot be
removed while enforcement is enabled. Disabling protection requires a current
passkey-authenticated session, confirmation from the locally unlocked vault,
and restores passphrase-only access.

**Lock vault** clears derived keys, decrypted transactions, charts, dashboard,
server view, and assistant content as far as JavaScript permits, but preserves
the passkey session. **Sign out** performs the same lock and invalidates the
server session, returning to the passkey screen when protection is enabled.

### WebAuthn configuration

Development uses `http://localhost:5000` with RP ID `localhost`; the equivalent
`http://127.0.0.1:5000` loopback origin is also accepted for local requests.
WebAuthn credentials are scoped to the RP ID and origin: do not switch between
`localhost` and `127.0.0.1` after enrollment. Configure deployments with:

```bash
VAULT_SECRET_KEY='a-long-random-deployment-secret'
VAULT_RP_ID='vault.example.com'
VAULT_ORIGIN='https://vault.example.com'
VAULT_RP_NAME='Vault'
VAULT_ENV='production'
VAULT_AUTH_POLICY='required'
```

Production fails at startup when the secret, RP ID, origin, or required policy is missing, or
when the origin is not HTTPS. It never derives these values from the request
Host header.

### Server-side authorization state

The browser cookie contains only a random 256-bit opaque identifier. Its
SHA-256 hash and the minimal session fields are stored in SQLite in
`server_sessions`; no passphrase, encryption key, plaintext, or credential
response is session data. Sessions have an eight-hour absolute lifetime and a
30-minute idle lifetime by default. Logout revokes the row immediately, and
successful registration, login, and policy transitions rotate both the
identifier and CSRF token. Cookies are HttpOnly, SameSite=Strict, Path `/`, and
Secure in production. Expired and revoked rows are cleaned opportunistically.

WebAuthn challenges live in `webauthn_challenges`, are bound to the initiating
server session and ceremony kind, expire after five minutes, and are consumed
with a conditional SQLite update before the first verification attempt. A
failed attempt consumes the challenge too, and all missing, mismatched,
expired, or consumed ceremonies produce the same generic error.

Every unsafe `/api/` request (`POST`, `PUT`, `PATCH`, or `DELETE`) requires both
the in-memory CSRF token from `GET /api/session` in `X-CSRF-Token` and an Origin
that exactly equals `VAULT_ORIGIN` by scheme, hostname, and effective port. The
only exception is the `localhost`/`127.0.0.1` alias in development; production
always requires an exact match.
Missing and `null` origins, suffix tricks, paths, user-info, alternate ports,
and cross-origin requests are rejected. There is no CORS wildcard or Host-based
origin inference.

### Ciphertext and resource limits

`POST /api/records` accepts only `application/json` with exactly this shape:

```json
{"records":[{"blind_index":"64 lowercase hex characters","sealed":"lowercase even-length hex"}]}
```

The whole batch is validated before an atomic upsert. Unknown fields,
duplicates, malformed blind indexes, and ciphertext outside 96–16384 hex
characters are rejected without partial writes. Defaults are an 8 MiB request
and JSON limit, 1,000 records per batch, and 100,000 total stored records. Byte
counts are computed from decoded hex on the server.

Configuration overrides are `VAULT_SESSION_TTL`, `VAULT_SESSION_IDLE_TTL`,
`VAULT_CHALLENGE_TTL`, `VAULT_MAX_REQUEST_BYTES`,
`VAULT_MAX_JSON_OBJECT_BYTES`, `VAULT_MAX_RECORDS_PER_BATCH`,
`VAULT_MAX_TOTAL_RECORDS`, `VAULT_MIN_SEALED_HEX_LENGTH`, and
`VAULT_MAX_SEALED_HEX_LENGTH`. `VAULT_HOST` and `VAULT_PORT` control the dev
listener; optional policy rejects a non-loopback host.

The database migrates in place on first access using idempotent `CREATE TABLE
IF NOT EXISTS` statements. Existing `records` rows and their encryption format
are not rewritten. The migration adds one `vault_identity` row for this
prototype's single local vault and a `passkey_credentials` table containing
credential IDs, public keys, counters, transports, backup/device state, labels,
and timestamps, plus server session and challenge tables. Existing record rows
and ciphertext are never rewritten. `passkey_required` changes to true only in the same transaction
that commits a successfully verified credential.

Set any passphrase, click **Connect demo bank**. Six months of transactions get
generated across a checking account, an IRA and a 401(k), encrypted in your
browser, and stored as ciphertext. The demo banks are Scammers Inc, Wells
Foreclosure and DC Unc. The checking feed includes a fixed $423.23 monthly
Fans Only subscription charge.

No network access required. Chart.js and libsodium are vendored in
`static/vendor/` rather than loaded from a CDN — a tool that promises the
server can't read your data shouldn't hand a third party the ability to swap
out its own crypto library.

## Tests

```bash
python -m pip install -r requirements.txt
python test_demo.py         # unit, crypto, privacy, WebAuthn/session tests
python test_browser.py      # real Chromium UI and virtual WebAuthn
```

## Production deployment

Production uses Gunicorn behind nginx over a protected Unix socket, never the
Flask development server or a public Gunicorn TCP listener. See
[`deploy/DEPLOYMENT.md`](deploy/DEPLOYMENT.md) for the dedicated service account,
TLS, exact-origin WebAuthn configuration, filesystem permissions, systemd
confinement, persistent rate limits, backup/restore, upgrades, and validation.

Flask emits a strict CSP (`default-src 'none'`, self-only scripts/styles/connect,
no inline handlers/styles, narrow `wasm-unsafe-eval` for vendored libsodium),
application security headers, sensitive-response `no-store`, and production
HSTS. `VAULT_CSP_MODE=report-only|enforce` selects the CSP header; production
defaults to enforcement. `VAULT_TRUST_PROXY=1` trusts exactly one controlled
proxy hop and must never be used with directly exposed Gunicorn.

Persistent SQLite rate-limit defaults are: general API 120/minute, session
60/minute, login options 20/5 minutes, login verification 10/10 minutes,
registration 10/hour, uploads 10/minute, relay 6/minute, record deletion
3/hour, passkey administration 5/hour, and logout 30/minute. Corresponding
`VAULT_RATE_*` environment variables adjust counts; window durations remain
fixed and should be changed only through reviewed code.

Covers the fake bank feed, the crypto, the API contract, and the privacy
guarantee. `BrowserSim` in that file reproduces `static/app.js` exactly — the
same passphrase and salts produce a byte-identical seed and public key in
PyNaCl and in browser libsodium, and one test pins that public key as a
regression vector. If Python and the browser ever diverge, that test fails
first and loudly.

```bash
pip install playwright && python3 -m playwright install chromium
python -m pip install playwright
python -m playwright install chromium
python test_browser.py             # includes Chromium virtual WebAuthn
python test_browser.py --headed    # watch it drive the browser
```

Exercises the actual JavaScript: real Argon2id in WASM, real Chart.js
rendering, the server-view toggle, reload persistence, and mobile layout. It
samples canvas pixels to confirm charts actually drew rather than just
existing, and asserts that no merchant name appears anywhere in the server
view's DOM. Screenshots land in `screenshots/`.

Two bugs these caught, both fixed:

- The hero figure showed the current month, which on the 2nd has rent but no
  paycheck — the largest number on the page read as a $2,773 loss.
- The four-column ledger overflowed at 390px. Category is hidden on phones now.

One test was written, failed, and then deleted rather than patched: a
file-wide scan for readable English words. Hex ciphertext abuts SQLite's
binary headers, so stray bytes manufacture pseudo-words — it flagged
`bfaeddvf`, and once `came` by chance. Tightening it enough to reject those
would also reject `coffee`, which has only one letter outside a–f. It was
replaced by a column-level check that every stored value is pure hex, which
is precise and cannot flake. A test you learn to ignore is worse than no test.

## The demo, in ninety seconds

1. Unlock with any passphrase. Key derivation takes ~350ms in the browser;
   that pause is Argon2id doing its job.
2. Connect the demo bank. Watch the label: *fetching*, then **encrypting in
   your browser**, then stored.
   If the vault already has the older demo feed, use **Refresh demo accounts**
   after unlocking to add the IRA and 401(k) records without duplicating
   checking transactions.
3. Look at the dashboard — spending by category, monthly flow, running
   balance, top merchants. All computed on-device from decrypted data.
4. Click **See what the server sees.** Same page, same data, rendered from the
   actual database table: blind indexes, hex blobs, blob-size histogram.
5. Ask **Ask your vault** for a summary, monthly totals, category breakdown,
   merchant totals or net cash flow. The assistant is deterministic browser
   code over the decrypted in-memory transactions; it makes no chat request,
   calls no model or API, and sends no plaintext to the server.
6. Close it in a terminal:

```bash
grep -c "Blue Bottle" demo.db     # 0
strings demo.db | grep -v '^[0-9a-f]*$' | head
```

Verified: all 26 merchant names absent from the database file. The only
readable strings are the schema.

## Why the encryption happens in the browser

Earlier drafts sealed records server-side, which is Proton's model and is
strong — but it means plaintext passes through a worker on every sync, and you
can't honestly say "encrypted client-side."

This uses a relay instead. `POST /api/relay` fetches from the bank and returns
plaintext **in the HTTP response**, writing nothing. The browser encrypts and
uploads ciphertext. Plaintext exists only inside one request the user
personally triggered — never in a database, a queue, or a background worker.

The cost: sync happens when the app is open, not at 3am. For a finance tracker
that's an acceptable trade, and it makes the core claim literally true.

`app.py` has no vault encryption keys. Its maintained `webauthn` dependency
parses authenticator data and verifies WebAuthn registrations and signatures;
that public-key authentication is separate from transaction encryption.

## What the server genuinely knows

Visible in the server view, because pretending otherwise would be dishonest:

- how many records exist
- when each was written (coarsened to the day)
- ciphertext length, which hints at merchant-name length

That last one is a real leak. Padding blobs to fixed 256-byte buckets closes
it and is about ten lines in the client. Left open deliberately so the server
view has something true to show.

It cannot recover any merchant, amount, date or category.

## Measured

| Operation | Time |
|---|---|
| Argon2id key derivation | ~350 ms |
| Encrypt 469 transactions | ~240 ms |
| Decrypt 469 transactions | ~90 ms |

Ten years of heavy usage is roughly 20 MB, so downloading the whole corpus and
computing every aggregate locally stays comfortable. No server-side query
capability is needed, which is fortunate — you couldn't build one without
weakening the encryption.

## Browser-only unusual activity detection

The dashboard reviews purchases locally with an explainable statistical
ensemble. Each purchase is compared only with earlier activity from the same
account over a rolling 180-day window. Signals include log-amount robust
z-scores (median/MAD with a standard-deviation fallback), empirical upper-tail
percentile, merchant novelty, merchant and category amount deviation, and
daily purchase velocity. Scoring starts only after 20 prior purchases.

Results are labeled **Review** or **Unusual**, never "fraud": the browser does
not have card authorization, device, location, identity, or network-level risk
signals. Every flag includes its contributing reasons and opens the encrypted
transaction editor. No transaction, baseline, score, or flag is sent to the
server.

The user can mark a statistical candidate **Safe** or **Fraud**, and can apply
the same review state to any transaction from the editor. Safe decisions are
suppressed from future flags while remaining part of the legitimate baseline;
user-confirmed fraud stays visible and is excluded from future baselines. The
review state is stored only inside the transaction ciphertext.

## Files

| File | Role |
|---|---|
| `static/app.js` | Key derivation, sealing, categorization, all chart math |
| `app.py` | Blob store and relay. No crypto, no keys |
| `fakebank.py` | Stand-in for the bank feed. Swap in the Plaid adapter here |
| `static/style.css` | Ledger aesthetic — Georgia's old-style figures, no webfonts |

## Demo shortcuts to remove

1. **Fixed salts** in `app.js` (`DEMO_SALT_ENC`, `DEMO_SALT_IDX`) so a reload
   re-derives the same key without a signup flow. Real builds generate random
   salts per user and store them next to the public key.
2. **Optional authentication.** Until passkey protection is explicitly enabled,
   any browser reaching this single-vault server can fetch its ciphertext and
metadata. Optional mode preserves compatibility; it does not protect users
who have not enabled it, and is deliberately restricted to loopback development.
3. **No recovery.** Forget the passphrase, lose the data. That's the honest
   consequence of the design; a real build adds a 24-word recovery phrase
   wrapping a second copy of the private key.
4. **Aggregator tokens** aren't wrapped here because there aren't any. When
   `fakebank` becomes Plaid, seal the access token under a KMS key.
5. **Flask dev server.** Obviously.

Additional threat-model limits remain: this is a single-vault prototype with
no account recovery or multi-user isolation; a compromised origin can replace
the JavaScript and steal the passphrase or plaintext; XSS runs with the user's
session; ciphertext count, timing, and length remain visible to the server once
authenticated (and always in passphrase-only mode); Flask's signed cookie does
and cloned/non-counter authenticators can limit sign-counter detection. Passkey
backup security depends on the platform provider. Use HTTPS, a hardened CSP,
trusted static deployment, rate limits,
and operational monitoring before production use.

## Next

Swap `fakebank.generate()` for the Plaid adapter from the earlier pipeline
work. Nothing downstream changes — the shapes already match.
