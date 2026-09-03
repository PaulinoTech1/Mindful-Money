# Vault — working prototype

A privacy-first finance tracker where the server stores your transactions and
cannot read them. Fake bank data, real cryptography, charts computed entirely
in your browser.

Storage is PostgreSQL, not a bundled file — bring up a local instance first
(the included `docker-compose.yml` is dev/test-only; see
[`deploy/DEPLOYMENT.md`](deploy/DEPLOYMENT.md) for production):

```bash
docker compose up -d
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
export VAULT_DATABASE_URL=postgresql+psycopg://vault:vault_dev_only_password@localhost:5432/vault_dev
alembic upgrade head
python app.py
# open http://localhost:5000
```

## Authentication policy and passkey protection

`VAULT_AUTH_POLICY` is explicit: `optional` or `required`. Development defaults
to `required`; set `VAULT_AUTH_POLICY=optional` only when bootstrapping a local
installation that has not enrolled a passkey yet. Optional mode may bind only
to a loopback host. Production has no optional default and refuses to start
unless `VAULT_AUTH_POLICY=required`. Required policy protects APIs
independently of whether a credential happens to have been enrolled; enroll a
passkey before using the protected local installation.

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
passkey-authenticated session, a browser-reported vault-open workflow
confirmation, and restores passphrase-only access. That browser report is a UX
gate, not cryptographic proof that the passphrase or encryption key is present.

**Lock vault** clears derived keys, decrypted transactions, charts, dashboard,
server view, and assistant content as far as JavaScript permits, but preserves
the passkey session. **Sign out** performs the same lock and invalidates the
server session, returning to the passkey screen when protection is enabled.

### Step-up authentication for passkey management

Adding another passkey, removing one, or disabling protection all require a
passkey authentication within `VAULT_STEPUP_WINDOW_SECONDS` (default 300) of
the request — a stale session that's merely "authenticated" per the normal
eight-hour session lifetime isn't enough for these specifically. This only
applies once a passkey already exists: first-time enrollment has no prior
passkey ceremony to be "recent" relative to, and stays gated by vault-unlock
alone, exactly as before.

Full server-side record deletion is stricter: `DELETE /api/records` always
requires at least one registered passkey, an authenticated session, and a
successful WebAuthn authentication assertion within
`VAULT_STEPUP_WINDOW_SECONDS` (default 300 seconds). This applies even in the
otherwise passphrase-only development policy. The web UI keeps the user's
explicit deletion confirmation, performs a passkey assertion when freshness is
missing, accepts the rotated CSRF token, and retries that confirmed deletion
once. A passkey must be enrolled explicitly before the full server-side vault
can be erased through either the UI or API.

`POST /api/vault/unlocked` is only a browser-to-server UI synchronization hint.
The Flask server never receives or verifies the passphrase, derived encryption
keys, recovery keys, plaintext records, or a passphrase verifier. Consequently,
`vault_unlocked=true` is not proof of vault-key possession, does not refresh
`authenticated_at`, and cannot authorize destructive deletion. In application
code, `authenticated_at` becomes fresh only after a successful server-side
`verify_authentication_response(...)` WebAuthn assertion.

### Audit log

`audit_events` is an append-only table recording `PASSKEY_REGISTERED`,
`PASSKEY_REMOVED`, `PASSKEY_AUTH_SUCCESS`, `PASSKEY_AUTH_FAILURE`,
`PASSKEY_PROTECTION_DISABLED`, `SESSION_REVOKED`, and
`SUSPICIOUS_COUNTER_EVENT`. Each row has a timestamp,
event type, the same HMAC-truncated client reference used for rate-limit
bucketing (not a raw IP), and — where relevant — a credential ID and a small
JSON detail blob. Never a challenge, session token, CSRF token, or public
key: the audit trail documents that something happened, not the
cryptographic material involved.

Successful full-record deletion emits the structured application security log
event `event="vault_records_deleted"` with the same privacy-preserving client
reference. It is intentionally not added to the database audit enum, avoiding
an unnecessary schema migration for this hardening change.

### Backend tenant isolation

`vault_identity.id` is the server-side tenant boundary. Every encrypted record
has a non-null foreign key to its identity, and `(identity_id, blind_index)` is
unique. All record uploads, downloads, quota calculations, server metadata,
ZKP challenge consumption, and deletions add the authenticated session's
identity to their database predicate. The API does not accept an identity ID
from request JSON, and record responses do not disclose one. A passkey
credential is globally unique and a successful sign-in resolves that
credential to its owning identity before rotating the session.

Migration `9c1e4a7b2d10` assigns all pre-migration records to identity 1 without
rewriting their blind indexes or ciphertext. Identity 1 remains the local
demo's compatibility tenant. New identities must be deliberately provisioned;
public signup, invitations, recovery, and account deletion are not implemented
yet. Production must continue to use `VAULT_AUTH_POLICY=required`.

A counter regression (an authenticator reporting a `signCount` that isn't
greater than what's on file, one signal of possible credential cloning) is
detected independently of whatever the `webauthn` library's own verification
raises, so it's audit-logged even on requests that also fail verification for
an unrelated reason.

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
SHA-256 hash and the minimal session fields are stored in PostgreSQL in
`server_sessions`; no passphrase, encryption key, plaintext, or credential
response is session data. Sessions have an eight-hour absolute lifetime and a
30-minute idle lifetime by default. Logout revokes the row immediately, and
successful registration, login, and policy transitions rotate both the
identifier and CSRF token. Cookies are HttpOnly, SameSite=Strict, Path `/`, and
Secure in production. Expired and revoked rows are cleaned opportunistically.
The retained `vault_unlocked` session column is compatibility-only,
browser-reported UI state; it is not an authentication factor. Session rotation
after WebAuthn authentication preserves that hint for workflow continuity but
does not make it more authoritative.

WebAuthn challenges live in `webauthn_challenges`, are bound to the initiating
server session and ceremony kind, expire after five minutes, and are consumed
with a conditional `UPDATE ... RETURNING` before the first verification
attempt — a single atomic statement under PostgreSQL's MVCC, with no
explicit locking needed. A
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
and JSON limit, 1,000 records per batch, and 100,000 stored records per tenant.
Byte counts are computed from decoded hex on the server.

Configuration overrides are `VAULT_SESSION_TTL`, `VAULT_SESSION_IDLE_TTL`,
`VAULT_CHALLENGE_TTL`, `VAULT_MAX_REQUEST_BYTES`,
`VAULT_MAX_JSON_OBJECT_BYTES`, `VAULT_MAX_RECORDS_PER_BATCH`,
`VAULT_MAX_TOTAL_RECORDS`, `VAULT_MIN_SEALED_HEX_LENGTH`, and
`VAULT_MAX_SEALED_HEX_LENGTH`. `VAULT_HOST` and `VAULT_PORT` control the dev
listener; optional policy rejects a non-loopback host.

Schema changes are Alembic migrations (`alembic upgrade head`), not something
the app does at runtime. The one thing the app still does on first request is
idempotently seed legacy identity 1 if it is missing — a cheap
`INSERT ... ON CONFLICT DO NOTHING`, not a schema change.
`passkey_credentials` holds credential IDs and public keys as raw bytes (not
base64url text — nothing about them needs text-safe encoding once SQLite's
TEXT-only columns are no longer the storage layer), counters, transports,
backup/device state, labels, and timestamps, alongside server session and
challenge tables. Existing record rows and ciphertext are never rewritten by
a migration. `passkey_required` changes to true only in the same transaction
that commits a successfully verified credential.

Set any passphrase, click **Connect demo bank**. Six months of transactions get
generated across a checking account, an IRA and a 401(k), encrypted in your
browser, and stored as ciphertext. The demo banks are Scammers Inc, Wells
Foreclosure and DC Unc. The checking feed includes a fixed $423.23 monthly
Fans Only subscription charge.

No *external* network access required — PostgreSQL is a local (or
operator-controlled) service, not a third party. Chart.js and libsodium are
vendored in `static/vendor/` rather than loaded from a CDN — a tool that
promises the server can't read your data shouldn't hand a third party the
ability to swap out its own crypto library.

## Tests

Needs the same PostgreSQL instance as above (`docker compose up -d`), plus a
`vault_test` database — the compose file creates one alongside `vault_dev`.
`ServerCase` truncates its tables between tests, so `VAULT_TEST_DATABASE_URL`
(defaults to `vault_test` on the same local instance) must point somewhere
disposable, never at a real deployment.

```bash
python -m pip install -r requirements.txt
python test_demo.py         # unit, crypto, privacy, WebAuthn/session/audit tests
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

Persistent PostgreSQL rate-limit defaults are: general API 120/minute, session
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
6. Close it in a terminal — there's no single database file to `strings`
   anymore, so query the columns directly instead:

```bash
psql postgresql://vault:vault_dev_only_password@localhost:5432/vault_dev \
    -At -c "SELECT sealed FROM records" | grep -c "Blue Bottle"     # 0
psql postgresql://vault:vault_dev_only_password@localhost:5432/vault_dev \
    -At -c "SELECT blind_index, sealed FROM records" | grep -v '^[0-9a-f,]*$' | head
```

Verified: all 26 merchant names absent, and every `blind_index`/`sealed`
value is pure hex.

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

## Local conversational projections

Money Chat keeps short-lived conversation context only in browser memory. It
can ask clarification questions, interpret a contextual "yes", and offer
clickable follow-up choices. Projection requests use reportable transactions
from complete months only, so partial-month rent or paycheck timing does not
distort the baseline.

Cash-flow and category projections use a robust Theil-Sen month-level trend.
Displayed ranges are based on median absolute historical residuals and are
explicitly described as historical variability, not a guaranteed outcome or a
large-sample confidence interval. At least three complete months are required.
Transfers and user-excluded transactions remain outside the model. Questions,
context, projections, and results never leave the browser.

## Files

| File | Role |
|---|---|
| `static/app.js` | Key derivation, sealing, categorization, all chart math |
| `app.py` | Blob store and relay. No crypto, no keys |
| `models.py` | SQLAlchemy models for the PostgreSQL schema |
| `db.py` | Request-scoped engine/session lifecycle |
| `migrations/` | Alembic migrations (`alembic upgrade head`) |
| `fakebank.py` | Stand-in for the bank feed. Swap in the Plaid adapter here |
| `simplefin.py` | SimpleFin Protocol adapter — normalizes a real (or demo) linked bridge into the same transaction shape as `fakebank.generate()` |
| `static/style.css` | Ledger aesthetic — Georgia's old-style figures, no webfonts |

## Connecting a real feed with SimpleFin

Set `SIMPLEFIN_ACCESS_URL` to a claimed SimpleFin access URL
(`https://<user>:<pass>@bridge.simplefin.org/simplefin`) to enable a second
**Connect via SimpleFin** button alongside the demo bank. `GET
/api/relay/sources` reports whether it is configured; the browser hides the
button when it is not. `POST /api/relay` accepts an optional
`{"source": "simplefin"}` body — omitted or `"fakebank"` keeps the existing
generated demo feed, `"simplefin"` fetches the last 90 days (SimpleFin's
range cap) from every linked account.

SimpleFin's amount sign convention is inflow-positive; `simplefin.py` negates
it on the way in so it matches this app's spend-positive, income-negative
convention documented in `fakebank.py`. Basic-auth credentials embedded in the
access URL are extracted and sent as an `Authorization` header — Python's
`urllib` does not parse userinfo out of the URL itself the way curl does.
Cloudflare, which fronts the SimpleFin bridge, also blocks the default
`urllib` User-Agent as bot traffic, so requests send a custom one.

The access URL is a bearer credential for a real (or demo) linked bridge; keep
it out of version control (`.env` is already gitignored) and treat it the way
you would any other aggregator token.

The environment-based SimpleFin credential is legacy identity 1's connection
only. Other identities receive "not configured" and cannot use or discover
that feed. A multi-user alpha still needs a per-identity connection table,
KMS-wrapped access URLs, and an explicit claim/revoke lifecycle before real
bank connections can be offered to those users.

## Demo shortcuts to remove

1. **Fixed salts** in `app.js` (`DEMO_SALT_ENC`, `DEMO_SALT_IDX`) so a reload
   re-derives the same key without a signup flow. Real builds generate random
   salts per user and store them next to the public key.
2. **Optional authentication.** Until passkey protection is explicitly enabled,
   any browser reaching the local demo can fetch compatibility tenant 1's
   ciphertext and metadata. Optional mode preserves backwards compatibility;
   it does not protect users who have not enabled it, and is deliberately
   restricted to loopback development.
3. **No recovery.** Forget the passphrase, lose the data. That's the honest
   consequence of the design; a real build adds a 24-word recovery phrase
   wrapping a second copy of the private key.
4. **Aggregator tokens aren't wrapped.** `SIMPLEFIN_ACCESS_URL` sits in plain
   process environment / `.env`. A real build seals it under a KMS key instead.
5. **Flask dev server.** Obviously.

Additional threat-model limits remain: database queries are tenant-isolated,
but there is no public account onboarding, invitation flow, account recovery,
per-user encryption salt provisioning, or per-user bank-connection lifecycle;
a compromised origin can replace the JavaScript and steal the passphrase or
plaintext; XSS runs with the user's session; ciphertext count, timing, and
length remain visible to the server once authenticated (and for compatibility
tenant 1 in passphrase-only mode); cloned/non-counter authenticators can limit
sign-counter detection. Passkey backup security depends on the platform
provider. Use HTTPS, a hardened CSP, trusted static deployment, rate limits,
and operational monitoring before production use.

## Next

SimpleFin now covers the "connect a real aggregator" case; Plaid remains the
option for institutions SimpleFin doesn't reach. Nothing downstream changes
either way — the shapes already match.
