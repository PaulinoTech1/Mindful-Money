# Hardening Proposals (not implemented)

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
