# Logging

**Last updated:** 2026-10-11

Mindful Money uses a two-tier logging setup: infrastructure logs in Google
Cloud Logging, and application audit events in Postgres.

## Tier 1: Cloud Logging (infrastructure)

Cloud Run automatically captures the app's stdout/stderr into Google Cloud
Logging. No configuration needed.

**What goes here:**
- Structured app logs (`event="passkey_auth_success"`, `event="rate_limited"`)
- Gunicorn access logs
- Python tracebacks and errors
- Cloud Run platform events (deploys, scaling, health checks)

**View logs:**
```bash
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=mindful-money" \
  --limit 20 --format json
```

Or in the GCP Console: Logging → Log Explorer → filter by `mindful-money`.

**Retention:** Default 30 days. Configurable in Cloud Logging settings.

**Cost:** 50 GiB/month free. This app generates far less than that.

## Tier 2: Postgres audit events (application)

The `audit_events` table is the application-level incident trail. Events are never
deleted. The `acknowledged_at`/`acknowledged_by` columns may be updated to mark
events as reviewed (this is a status update, not a modification of the event
itself). For strict append-only auditing, query the `INCIDENT_ACKNOWLEDGED`
events rather than relying on the acknowledgment columns.

**Event types:**
- `PASSKEY_REGISTERED` / `PASSKEY_REMOVED`
- `PASSKEY_AUTH_SUCCESS` / `PASSKEY_AUTH_FAILURE`
- `PASSKEY_PROTECTION_DISABLED`
- `SESSION_REVOKED`
- `SUSPICIOUS_COUNTER_EVENT` (WebAuthn sign count regression)
- `UNUSUAL_ACTIVITY_DETECTED` (browser-side detector)
- `INCIDENT_ACKNOWLEDGED` (analyst marked an event as reviewed)
- `HONEYPOT_HIT` (attacker probed a honeypot endpoint like /wp-admin)
- `ACCOUNT_LOCKED` (5+ failed logins in 15 min triggered 30-min lockout)
- `STEP_UP_REQUIRED` (destructive op attempted without fresh auth)

**Incident response API:**
- `GET /api/audit/events` - list events (filter by `event_type`, paginate with `limit`/`offset`)
- `POST /api/audit/events/<id>/acknowledge` - mark as reviewed

Both require authentication.

## Opt-in IP address logging

**Default: OFF.** The app is privacy-first. By default, audit events store
only a HMAC-truncated `client_ref` (12 hex chars derived from the IP with a
server-side secret). This supports rate-limit bucketing without storing
identifiable IPs.

### Enabling

Set the environment variable:
```bash
VAULT_IP_LOGGING=on
```

On Cloud Run:
```bash
gcloud run deploy mindful-money \
  --region us-central1 \
  --update-env-vars "VAULT_IP_LOGGING=on"
```

Or add it to the GitHub Actions workflow's `--set-env-vars`.

### What changes

When `VAULT_IP_LOGGING=on`:
- `audit_events.client_ip` stores the full client IP (IPv4 or IPv6)
- `client_ref` (HMAC-truncated) is still stored as before

When `off` (default):
- `audit_events.client_ip` is NULL
- Only the HMAC-truncated `client_ref` is stored

### Privacy implications

Enabling IP logging means:
- Client IP addresses are stored in Neon Postgres
- IPs are PII under GDPR/CCPA
- Access to the `audit_events` table must be controlled accordingly
- Consider your data retention policy for the audit table

**Recommendation:** Keep it off unless you need IPs for active incident
investigation. The HMAC-truncated `client_ref` is sufficient for correlating
events from the same client without storing PII.

### Disabling

Set `VAULT_IP_LOGGING=off` or remove the variable. Existing `client_ip`
values in the database are not automatically purged. To purge:
```sql
UPDATE audit_events SET client_ip = NULL;
```

## Detection logging

The `_log_detection()` helper in `app.py` logs unusual activity detections
to the audit trail:

```python
_log_detection("rapid_requests", {"count": 150, "window_seconds": 60})
```

This creates a `UNUSUAL_ACTIVITY_DETECTED` audit event with the detection
type and details in the `detail` JSON column. Detection events are always
logged regardless of the IP logging setting.

## What is NOT logged

- Passphrases or derived keys (never leave the browser)
- Financial plaintext or decrypted records
- WebAuthn challenges, session tokens, or private keys
- SimpleFin credentials (handled entirely client-side)

## Audit log retention

**Policy:** Audit events are retained indefinitely by default.

**Rationale:** Security events (auth failures, suspicious counters) are valuable
for forensic analysis. The volume is low (tens of events per day, not thousands).

**If retention becomes a concern:**
```sql
-- Delete events older than 1 year (example)
DELETE FROM audit_events WHERE occurred_at < NOW() - INTERVAL '1 year';
```

**GDPR note:** Audit events contain `client_ref` (HMAC-truncated) and optionally
`client_ip` (if opt-in enabled). These may be considered personal data. If a user
requests erasure, delete their audit events:
```sql
DELETE FROM audit_events WHERE identity_id = <USER_ID>;
```

**Recommendation:** Keep security events (SUSPICIOUS_COUNTER_EVENT,
PASSKEY_AUTH_FAILURE) for at least 1 year. Other events can be purged after
90 days if storage becomes a concern.
