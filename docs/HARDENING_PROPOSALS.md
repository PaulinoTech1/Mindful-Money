# Hardening Proposals and Roadmap

**Date:** 2026-10-13
**Status:** proposals. P1 is implemented (see below); everything else is not. Each item
needs the owner's go-ahead. Philosophy: the app does not need to be
invincible; it needs to break on its own terms (loudly, predictably,
documented).

## P1. Log the SQLAlchemyError 503 handler

**Status (2026-10-13): implemented, locally tested.** Not CI-verified, not
production-verified. Confidence high for redaction of the tested shapes
(URL, user@host, password=/user=/host= pairs, IPs, dotted hostnames,
quoted host/user names, `(key)=(value)` details, `[SQL: ...]` and
`[parameters: ...]` tails); medium for driver messages of shapes not seen yet.
Code: `app.py` `_redact_db_detail()`, `database_error()`, and `/ready`.
Tests: `test_db_error_logging.py` (3 tests: `/api/*` 503 body and status
unchanged and log redacted, `/ready` redacted, redactor unit). Full local
suite: 144 passed (Python 3.13, Postgres 17; CI uses 3.12 and 16).
Log line: `event="db_error" class=... orig_class=... sqlstate=... path=... detail=...`
at ERROR, so `severity>=ERROR` in RUNBOOK "View logs" catches it.
The original proposal follows for the record.

**Symptom:** during the 2026-10-12 `_seed_identity` outage every `/api/*`
call returned 503 and Cloud Logging showed nothing
(`docs/CLOUD_RUN_TROUBLESHOOTING.md`, "_seed_identity NotNullViolation").

**Evidence:** `app.py` `database_error()` returns
`api_error("The request could not be completed", 503)` without logging.

**Root cause:** the handler was written to avoid leaking DB detail to
clients, and over-corrected by also hiding it from the operator.

**Proposed fix (client response unchanged):**

```python
_SQL_SECRETS = re.compile(r"(postgres(?:ql)?(?:\+\w+)?://)\S+", re.I)

@app.errorhandler(SQLAlchemyError)
def database_error(error):
    # Class name and the DB driver's first line only. Never the URL, the
    # statement, or bound parameters (they can hold ciphertext, blind
    # indexes, salts or session hashes).
    orig = getattr(error, "orig", None)
    detail = str(orig if orig is not None else error).splitlines()[0][:200]
    detail = _SQL_SECRETS.sub(r"\1<redacted>", detail).replace('"', "'")
    LOG.error('event="db_error" class="%s" orig_class="%s" sqlstate="%s" '
              'path="%s" detail="%s"',
              type(error).__name__, type(orig).__name__ if orig else "",
              getattr(orig, "sqlstate", "") or "", request.path, detail)
    return api_error("The request could not be completed", 503)
```

Notes:
- Do NOT log `str(error)`: SQLAlchemy appends `[SQL: ...]` and
  `[parameters: ...]` to it. `error.orig` (the psycopg error) does not.
- `sqlstate` (for example `23502` not-null, `42703` undefined column) would
  have named both 2026-10-12 and 2026-10-13 root causes in one log line.
- Emit at ERROR so `severity>=ERROR` (RUNBOOK "View logs") catches it.
- Apply the same redaction to `/ready`, which currently logs `str(e)[:100]`
  and can include the DB host and user.
- Test: a pytest that forces a `NotNullViolation` and asserts the log line
  contains `sqlstate="23502"` and contains neither `postgresql` nor any bound
  value.

**Risk of the change:** low. Response bodies are unchanged.

## P2. Pin Secret Manager versions instead of :latest (infra)

`deploy.yml` uses `mindful-money-secret:latest` and `neon-db-url:latest`.
A bad new version (as v4 was on 2026-10-13) goes live on the next cold
start with no deploy and no review. Proposal: pin numeric versions in
`deploy.yml` (for example `neon-db-url:5`, after confirming v5 is the live
one) and rotate by PR. Trade-off: rotation then requires a deploy.

## P3. Disable, then destroy, neon-db-url versions 1 to 3 (infra)

They hold the pre-rotation password. If the Neon password was actually
rotated on the Neon side they are dead credentials, but disabling them
removes any doubt. Disable first (reversible), destroy after a week.

## P4. Remove the bootstrap token after first passkey enrollment (infra)

See `docs/THREAT_MODEL.md` risk register and `docs/BOOTSTRAP_TOKEN.md`.
**Status (2026-10-13):** approved. The first production passkey is enrolled
(`/api/passkeys/status` reports `bootstrap_needed: false`). The token is not
set by `deploy.yml`, so it is a live Cloud Run binding; removal needs
`gcloud` with project access (commands in `docs/BOOTSTRAP_TOKEN.md`). Not
yet done.

## P5. Run migrations as a gated deploy step (CI/infra)

Migrations are manual (`docs/RUNBOOK.md`). Option: a Cloud Run Job using an
unpooled-URL secret that runs `alembic upgrade head` before
`gcloud run deploy`, plus a smoke check that `alembic current` equals
`alembic heads`. Needs a new secret and IAM; owner decision.

## P6. Loud rate-limiter DB failures

`apply_rate_limit` writes to Postgres on every `/api/*` request (accepted
coupling, `docs/THREAT_MODEL.md`). With P1 in place the failure becomes
visible. Optionally add a distinct `event="rate_limit_db_error"` so alerts
can tell "limiter down" from "route down". Keep fail-closed.

## Roadmap: ASVS-aligned assurance items (2026-10-13)

Verification framework: OWASP ASVS 5.0; current status per requirement in
[ASVS.md](ASVS.md). Each item names the threat it addresses and a priority
(the owner's). None is implemented yet. The residual risk each one reduces
is stated in its primary doc and only linked here.

### R1. Independent-origin production hash verification

**Threat:** origin compromise ([THREAT_MODEL.md](THREAT_MODEL.md#dominant-residual-risk)).
**Priority:** Low.
Today the deploy workflow checks served JS hashes right after deploy, from
the same pipeline that shipped it ([JS_INTEGRITY.md](JS_INTEGRITY.md)). Proposal:
a scheduled job outside the deploy path (a separate GitHub Actions workflow
on a cron, or an external monitor) fetches the served `app.js`,
`simplefin-client.js`, `recovery-words.js` and vendored libraries from the
canonical host and compares them with the manifest at the tagged commit in
git, alerting on mismatch. Detects later tampering at the origin; cannot
stop a simultaneous repo and pipeline compromise. ASVS: supports 3.6.1 and
the V15 inventory items.

### R2. GitHub and Cloud Run deployment authorization hardening

**Threat:** origin compromise via the pipeline
([THREAT_MODEL.md](THREAT_MODEL.md#actors), "Malicious deploy pipeline").
**Priority:** Low-Medium.
Proposal: branch protection on `main` with required checks (verify,
browser-test, CodeQL) and a required review; a protected GitHub
environment for the deploy job; Workload Identity Federation scoped to this
repo and branch; a deploy service account limited to Cloud Run deploy and
the two secrets; audit of who holds Owner/Editor on the project; pinned
action versions by commit SHA. ASVS: 13.3.2 (least-privilege secret
access). Needs project IAM access; owner decision.

### R3. Explicit zeroization and automatic vault locking

**Threat:** endpoint compromise or an unattended unlocked browser.
**Priority:** Low.
Today `lockVault()` zeroes the private, index and public key buffers and
clears decrypted transactions; recovery wipes its key material. Gaps: no
idle or tab-hidden auto-lock; derived seeds and intermediate buffers are
not all wiped; JavaScript strings (decrypted JSON) cannot be zeroed. Proposal:
auto-lock after a configurable idle period (default 10 min) and optionally
when the tab is hidden; wipe every `Uint8Array` that held key material
after use; document the string limitation. ASVS: 14.3.1; 11.7.1 stays out
of reach for a browser app.

### R4. Malicious-JavaScript and plaintext-leak regression tests

**Threat:** verification gap (a future change that sends plaintext,
keys or the passphrase to the server or elsewhere would not be caught
everywhere).
**Priority:** Medium.
Today the browser tests assert that the passphrase never appears in request
bodies and that edits reach the server only as ciphertext. Proposal: a
Playwright suite that records every request (all hosts, headers, bodies,
URLs) through a full session (connect, edit, manual entry, CSV import,
recovery, rekey) and fails on any plaintext marker, key bytes or passphrase;
plus a negative test that injects a deliberately leaking script and
confirms CSP and the tests catch it. ASVS: supports 14.2.3 and 3.4.3.

### R5. Focused external code review

**Threat:** lack of independent assurance.
**Priority:** Moderate.
Scope already drafted in [AUDIT_SCOPE.md](AUDIT_SCOPE.md): sealing and
padding, KDF and salts, recovery and rekey, session and step-up, tenant
isolation. Deliverable: findings mapped to [ASVS.md](ASVS.md) requirement
IDs, after which rows move to "reviewed". Needs budget; owner decision.

### R6. Versioned security verification report

**Threat:** verification drift (claims in docs going stale).
**Priority:** Low.
Proposal: a dated, versioned report per release (`docs/verification/`)
generated from [ASVS.md](ASVS.md), recording the commit, CI run IDs,
production header and smoke results, open gaps, a cryptographic inventory
(ASVS 11.1.2), a dependency inventory or SBOM (15.1.2) and written
remediation time frames (15.1.1).

### R7. Restrict unnecessary browser network destinations

**Threat:** partial JavaScript compromise (an injected script exfiltrating
to an arbitrary host). The risk itself is the `connect-src` row of the
[THREAT_MODEL.md](THREAT_MODEL.md#risk-register) risk register.
**Priority:** not assigned by the owner.
Today CSP allows `connect-src 'self' https:` because the SimpleFin bridge
host is user-supplied. Proposal: narrow to `'self'` plus the SimpleFin
bridge hosts (for example `https://bridge.simplefin.org` and
`https://beta-bridge.simplefin.org`), with the client refusing other hosts
and a clear error; document every destination (ASVS 13.1.1). Not changed in
this round: it would break any self-hosted or alternative bridge, which is
a product decision. Zero-knowledge is unaffected either way.
