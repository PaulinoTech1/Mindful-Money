# Vault — working prototype

## TL;DR

A privacy-first personal finance tracker (Vault). Client-side encryption, passkeys, and memory-hard key derivation mean the server never sees your plaintext. Goal: personal finance software you do not have to trust with your data.

**Architecture update (2026-10-11):** The server-side bank relay (`/api/relay`,
`fakebank.py`, `simplefin.py`) has been removed. Bank data ingestion is now
entirely client-side via `static/simplefin-client.js`. The server never sees
plaintext transactions. See `docs/TRUST_BOUNDARIES.md` for the honest trust
model.

**KDF salts (2026-10-11):** Fixed `DEMO_SALT_ENC`/`DEMO_SALT_IDX` have been
replaced with per-identity server-side salts (`/api/kdf/salts`). See
`docs/TRUST_BOUNDARIES.md`.

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
public signup, invitations, and account deletion are not implemented yet
(passphrase recovery with a recovery key is: [docs/RECOVERY.md](docs/RECOVERY.md)). Production must continue to use `VAULT_AUTH_POLICY=required`.

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
duplicates, malformed blind indexes, and ciphertext outside 96 to 16480 hex
characters are rejected without partial writes. 16480 is exact: the largest
client padding bucket is 8192 bytes and a NaCl sealed box adds 48
(`crypto_box_SEALBYTES`: 32-byte ephemeral public key plus 16-byte MAC), so
8240 bytes, 16480 hex. Raise it only together with `PAD_BUCKETS` in
`static/app.js`. Defaults are an 8 MiB request
and JSON limit, 500 records per batch, and 100,000 stored records per tenant.
Byte counts are computed from decoded hex on the server.

500 records per batch is derived so that a worst-case batch always fits the
8 MiB request limit. In compact JSON one record is
`{"blind_index":"<64 hex>","sealed":"<16480 hex>"}` = 30 + 64 + 16480 =
16574 bytes, plus 1 for the separating comma, and the wrapper
`{"records":[]}` is 14 bytes. So N records take at most 14 + 16575 N bytes,
and 14 + 16575 N <= 8,388,608 gives N <= 506. 500 leaves margin: 14 +
500 x 16575 = 8,287,514 bytes. `test_kdf_migrate_and_limits.py` asserts this
invariant against the configured values; if you raise any of these limits,
keep it true. The browser (`uploadSealedRecords` in `static/app.js`) splits
every bulk upload (connect, CSV import, backup restore, re-encryption) into
chunks of at most 500 records and 6 MiB of body, so no client request can hit
either limit. Each chunk is atomic, but a multi-chunk upload is not atomic as
a whole: if a later chunk fails, earlier chunks stay stored. Uploads are
upserts keyed by blind index, so retrying the same operation converges.
`MAX_REQUEST_BYTES` is deliberately not raised: Cloud Run caps HTTP/1 request
bodies at 32 MiB, and a larger limit only widens the memory and parsing DoS
surface.

`POST /api/records` is rate limited to 60 requests per 60 s fixed window,
keyed per vault identity when signed in and per client IP (HMAC of the
trusted remote address) otherwise. Derivation: every single edit (manual
entry, edit, rename, fraud flag) is one request, and a fast user does well
under one edit per second for a sustained minute; 30 edits in a minute is
the realistic burst the tests accept. A bulk sync is a few chunks (1,200
records is 3 chunks), so 60 covers a burst of edits plus several syncs with
2x headroom over the 30-edit burst. The previous 10 was hit by ordinary
editing. Abuse bound: 60 requests of at most 8 MiB is about 480 MiB per
minute per identity, still bounded by the 100,000-record tenant cap for
storage; the fixed window allows up to 2x at a window boundary. An upload
larger than 60 chunks (tens of thousands of records) waits for the 429
`Retry-After` and retries the same chunk, up to 3 times per chunk.

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

Set any passphrase, click **Connect demo bank**. Twelve months of
transactions for a fictional dual-income household (the Carters, see
[docs/DEMO_DATASET.md](docs/DEMO_DATASET.md)) get generated across joint
checking, a rewards credit card, an emergency fund, a 401(k), a Roth IRA and a
brokerage account, encrypted in your browser, and stored as ciphertext. The
financial institutions are fictional; merchants are mainstream brands.

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

### Cloud Run deployment

The recommended managed deployment is Google Cloud Run. See
[`docs/HOSTING_DECISION.md`](docs/HOSTING_DECISION.md) for why Cloud Run was
chosen over Vercel, Render, and other options.

```bash
# From Google Cloud Shell (already authenticated)

# Enable required APIs (one-time)
gcloud services enable run.googleapis.com secretmanager.googleapis.com cloudbuild.googleapis.com

# Create secrets
openssl rand -base64 64 | tr -d '\n' | gcloud secrets create mindful-money-secret --data-file=-
echo -n "YOUR_NEON_URL" | gcloud secrets create neon-db-url --data-file=-

# Deploy (private - no --allow-unauthenticated)
gcloud run deploy mindful-money \
  --source . \
  --region us-central1 \
  --set-env-vars "VAULT_ENV=production,VAULT_AUTH_POLICY=required,VAULT_RP_ID=placeholder,VAULT_ORIGIN=https://placeholder,VAULT_TRUST_PROXY=1,VAULT_CSP_MODE=enforce" \
  --set-secrets "VAULT_SECRET_KEY=mindful-money-secret:latest,VAULT_DATABASE_URL=neon-db-url:latest"

# Grant yourself access (private service)
gcloud run services add-iam-policy-binding mindful-money \
  --region us-central1 \
  --member="user:YOUR_EMAIL@gmail.com" \
  --role="roles/run.invoker"

# Update RP_ID and ORIGIN to the real URL, then redeploy
gcloud run deploy mindful-money \
  --region us-central1 \
  --update-env-vars "VAULT_RP_ID=actual-host.run.app,VAULT_ORIGIN=https://actual-host.run.app"
```

See [`docs/CLOUD_RUN_TROUBLESHOOTING.md`](docs/CLOUD_RUN_TROUBLESHOOTING.md)
for common deployment issues and fixes.

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
    -At -c "SELECT sealed FROM records" | grep -c "Harris Teeter"   # 0
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
- ciphertext length, rounded up to a padding bucket

Records are padded in the browser before encryption, so the server sees only
the bucket size. Format, buckets and the remaining metadata risk:
[docs/TRUST_BOUNDARIES.md](docs/TRUST_BOUNDARIES.md#what-the-server-can-see).

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
| `app.py` | Blob store and API. No vault crypto, no keys |
| `models.py` | SQLAlchemy models for the PostgreSQL schema |
| `db.py` | Request-scoped engine/session lifecycle |
| `migrations/` | Alembic migrations (`alembic upgrade head`) |
| `static/simplefin-client.js` | Browser-side SimpleFin client, CSV parser and the demo dataset ([docs/DEMO_DATASET.md](docs/DEMO_DATASET.md)) |
| `static/style.css` | Ledger aesthetic — Georgia's old-style figures, no webfonts |

## Connecting a real feed with SimpleFin

**Connect via SimpleFin** prompts for a SimpleFin access URL in the browser,
fetches the last 90 days there, and encrypts the transactions before upload
(`static/simplefin-client.js`). The access URL is never stored or sent to this
server. Provider trust: [docs/TRUST_BOUNDARIES.md](docs/TRUST_BOUNDARIES.md#provider-trust-simplefin-and-banks).

## Demo shortcuts to remove

1. **Optional authentication.** Until passkey protection is explicitly enabled,
   any browser reaching the local demo can fetch compatibility tenant 1's
   ciphertext and metadata. Optional mode preserves backwards compatibility;
   it does not protect users who have not enabled it, and is deliberately
   restricted to loopback development.
2. **No recovery without a recovery key.** Forget the passphrase without
   having set up a recovery key and the data is lost. With one, recovery
   works end to end ([docs/RECOVERY.md](docs/RECOVERY.md)).
3. **Flask dev server** for local runs. Production runs Gunicorn on Cloud Run.

Additional threat-model limits remain: database queries are tenant-isolated,
but there is no public account onboarding, invitation flow, or recovery of a
lost passkey without a backup passkey;
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
