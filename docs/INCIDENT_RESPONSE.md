# Incident Response Runbook

**Last updated:** 2026-10-11
**Cost:** $0 (uses Google Cloud free tier only)

This runbook covers detecting, triaging, and responding to security incidents
in Mindful Money using Google Cloud's native tools. No third-party services,
no additional cost.

## Detection: Log-based alerts

All alerts use Cloud Logging log-based metrics + Cloud Monitoring alert
policies. Free tier covers this workload.

### Setup

Create log-based metrics for each detection pattern:

```bash
PROJECT="project-c89a7f58-b865-4112-bf8"
SERVICE="mindful-money"

# 1. Suspicious WebAuthn counter (possible cloned authenticator)
gcloud logging metrics create mm_suspicious_counter_event \
  --project=$PROJECT \
  --description="WebAuthn sign count regression - possible cloned authenticator" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND textPayload:\"event=\\\"suspicious_counter_event\\\"\""

# 2. Passkey auth failures (brute force indicator)
gcloud logging metrics create mm_authentication_failures \
  --project=$PROJECT \
  --description="Passkey authentication failures" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND textPayload:\"event=\\\"authentication_failure\\\"\""

# 3. Unusual activity detections
gcloud logging metrics create mm_unusual_activity \
  --project=$PROJECT \
  --description="Browser-side unusual activity detector triggered" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND textPayload:\"event=\\\"unusual_activity_detected\\\"\""

# 4. Rate limiting (potential abuse)
gcloud logging metrics create mm_rate_limited \
  --project=$PROJECT \
  --description="Rate limit hits" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND textPayload:\"event=\\\"rate_limited\\\"\""

# 5. Application errors
gcloud logging metrics create mm_app_errors \
  --project=$PROJECT \
  --description="Application errors and exceptions" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND severity>=ERROR"
```

### Alert policies

Create alert policies in Cloud Monitoring for each metric. Example for the
critical suspicious counter alert:

```bash
# Alert immediately on any suspicious counter event
gcloud alpha monitoring policies create \
  --project=$PROJECT \
  --display-name="Mindful Money: Possible cloned authenticator" \
  --condition-display-name="Suspicious WebAuthn counter" \
  --condition-filter="metric.type=\"logging.googleapis.com/user/mm_suspicious_counter_event\"" \
  --condition-threshold-value=1 \
  --condition-threshold-comparison="COMPARISON_GT" \
  --condition-threshold-duration="0s" \
  --notification-channels="<YOUR_CHANNEL_ID>"
```

**Recommended thresholds:**

| Alert | Threshold | Severity | Action |
|-------|-----------|----------|--------|
| Suspicious counter | > 0 in 1 min | Critical | Immediate investigation |
| Auth failures | > 5 in 5 min | High | Check for brute force |
| Unusual activity | > 3 in 10 min | Medium | Review audit events |
| Rate limited | > 20 in 5 min | Medium | Check for abuse/scraping |
| App errors | > 10 in 5 min | High | Check Error Reporting |

### Notification channels

Set up once in Cloud Monitoring:
- Email (free)
- SMS via email gateway (free)
- Webhook to your preferred tool (free)

```bash
gcloud alpha monitoring channels create \
  --project=$PROJECT \
  --display-name="Security alerts" \
  --type="email" \
  --channel-labels=email_address=your@email.com
```

## Triage: What to check

### 1. Cloud Logging

```bash
# Recent suspicious events
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=\"mindful-money\" AND (textPayload=~"event=\"suspicious_counter_event\" OR textPayload=~"event=\"authentication_failure\")" \
  --limit 20 --format json --freshness 1h
```

### 2. Audit events API

```bash
# List recent security events (requires auth)
curl -s -b "vault_session=<SESSION>" \
  "https://mindful-money-k23ukkh5cq-uc.a.run.app/api/audit/events?event_type=SUSPICIOUS_COUNTER_EVENT&limit=20"
```

### 3. Error Reporting

GCP Console → Error Reporting → filter by `mindful-money`. Shows grouped
exceptions with stack traces.

### 4. Cloud Audit Logs

```bash
# Who changed what in GCP (IAM, deploys, secret access)
gcloud logging read \
  "protoPayload.serviceName=\"run.googleapis.com\" AND protoPayload.methodName contains \"mindful-money\"" \
  --limit 20 --format json --freshness 24h
```

## Response procedures

### Possible cloned authenticator (SUSPICIOUS_COUNTER_EVENT)

**Severity:** Critical

1. Acknowledge the audit event: `POST /api/audit/events/<id>/acknowledge`
2. Check Cloud Logging for the full context (which credential, when)
3. If confirmed: remove the compromised passkey via `POST /api/passkeys/remove`
4. User re-enrolls a new passkey
5. Review all sessions: `POST /api/session/revoke` to force re-auth
6. Document in the audit trail

**Why this matters:** WebAuthn sign counts should only increase. A regression
means the authenticator was likely cloned.

### Brute force attempt (multiple PASSKEY_AUTH_FAILURE)

**Severity:** High

1. Check if failures are from the same `client_ref`
2. If opt-in IP logging is on, check `client_ip` for the source
3. Rate limiting should already be throttling the attacker
4. If persistent: consider temporarily blocking at Cloud Armor (free tier
   available) or reviewing WAF rules
5. Acknowledge events after review

### Unusual activity detected

**Severity:** Medium

1. Review the detection details in the audit event `detail` field
2. Correlate with Cloud Logging for the same timeframe
3. Determine if legitimate user behavior or actual threat
4. Acknowledge after review

### Application errors spike

**Severity:** High

1. Check Error Reporting for grouped exceptions
2. Check Cloud Run logs for the specific errors
3. If deployment-related: roll back via Cloud Run revisions
4. If attack-related: treat as potential incident

## Dashboard

Create a Cloud Monitoring dashboard for at-a-glance status:

**Widgets to include:**
- Auth success/failure rate (from `mm_authentication_failures` metric)
- Suspicious counter events (from `mm_suspicious_counter_event`)
- Request rate and latency (automatic Cloud Run metrics)
- Error rate (from `mm_app_errors`)
- Instance count (automatic Cloud Run metric)

```bash
# Cloud Run metrics are automatic; just add them in the Console:
# Monitoring → Dashboards → Create → Add widgets
# Resource type: Cloud Run Revision
# Service: mindful-money
```

## Cost

All of the above uses:
- Cloud Logging: 50 GiB/month free (this app uses < 1 GiB)
- Cloud Monitoring: free tier covers 150+ metrics
- Log-based metrics: free
- Alert policies: free (email/webhook notifications)
- Error Reporting: free
- Cloud Audit Logs: free
- Security Command Center Standard: free

**Total additional cost: $0.**

## What this does NOT cover

- **SIEM integration:** No Splunk/Datadog. Cloud Logging is the SIEM.
- **Automated response:** Alerts notify; human responds. No auto-blocking
  (except built-in rate limiting).
- **Forensic disk images:** Cloud Run is stateless; no disks to image.
  Postgres audit trail is the forensic record.
- **Threat intel feeds:** Not integrated. Manual correlation only.

## Browser vs server monitoring

**Important distinction:**

- **Server-side security events** (in Cloud Logging): authentication failures,
  suspicious WebAuthn counters, rate limiting, errors. These indicate attacks
  against the server.

- **Browser-side unusual activity** (in audit_events table): The
  `_log_detection()` helper logs client-detected anomalies (e.g., rapid
  requests, unusual patterns). These are **not** server-observed security
  events. They indicate potential client-side issues or user behavior anomalies,
  not server attacks.

Do not treat `UNUSUAL_ACTIVITY_DETECTED` audit events as evidence of a server
security incident. They are informational for the user, not for SOC triage.

The log-based alerts above cover server-side events only. Browser detections
are visible via the `/api/audit/events` API, not via Cloud Logging alerts
(unless you specifically create an alert for the `unusual_activity_detected`
log line, which is now emitted by `_log_detection()`).

## Database backup and recovery (Neon)

Neon provides automatic point-in-time recovery (PITR).

**What's backed up:**
- Full database, continuous WAL archiving
- Retention: depends on Neon plan (check console for current setting)
- RPO: seconds (WAL-based)
- RTO: minutes (branch restore)

**To verify backups are working:**
1. In Neon console, check the "Branches" tab for restore points
2. Create a test branch from a PITR timestamp (non-destructive)
3. Verify data is present in the test branch
4. Delete the test branch

**To recover from data loss:**
```bash
# Via Neon console:
# 1. Go to Branches → "Create branch from PITR"
# 2. Select timestamp before the incident
# 3. Once verified, promote the branch or copy the connection string
# 4. Update VAULT_DATABASE_URL in Secret Manager
# 5. Redeploy Cloud Run to pick up the new secret
```

**Important:** Test this procedure before you need it. A backup you've never
restored is not a backup.

## Uptime monitoring setup

Create a Cloud Monitoring uptime check for the `/health` endpoint.

```bash
PROJECT="project-c89a7f58-b865-4112-bf8"

# Create uptime check (via console: Monitoring → Uptime checks → Create)
# - Resource type: URL
# - Host: mindful-money-k23ukkh5cq-uc.a.run.app
# - Path: /health
# - Check interval: 5 minutes
# - Timeout: 10 seconds

# Create alert policy for downtime
gcloud alpha monitoring policies create \
  --project=$PROJECT \
  --display-name="Mindful Money: Uptime check failed" \
  --condition-display-name="Health check failing" \
  --condition-filter='metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND metric.label.check_id="<CHECK_ID>"' \
  --condition-threshold-value=1 \
  --condition-threshold-comparison="COMPARISON_LT" \
  --condition-threshold-duration="600s" \
  --notification-channels="<CHANNEL_ID>"
```

Replace `<CHECK_ID>` and `<CHANNEL_ID>` with values from the console.

## Rate limits (current configuration)

| Endpoint group | Limit | Window | Purpose |
|---------------|-------|--------|---------|
| general | 120 | 60s | Default API rate |
| session | 60 | 60s | Session endpoints |
| login_options | 20 | 5min | Passkey login initiation |
| login_verify | 10 | 10min | Passkey verification (brute force protection) |
| registration | 10 | 1hr | Passkey registration |
| upload | 10 | 60s | Record uploads |
| delete | 3 | 1hr | Destructive operations |
| zkp_challenge | 20 | 5min | ZKP challenge generation |
| zkp_verify | 10 | 5min | ZKP proof verification |
| passkey_admin | 5 | 1hr | Passkey management |
| logout | 30 | 60s | Logout |

All limits are configurable via `VAULT_RATE_*` environment variables.
Rate limit hits are logged as `event="rate_limited"` and can trigger alerts.

## Secrets rotation procedures

### Flask secret key (VAULT_SECRET_KEY)

**Impact:** Invalidates all sessions. Users must re-authenticate.

```bash
# 1. Generate new secret (32+ random bytes, hex-encoded)
NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 2. Add new version to Secret Manager (do NOT destroy old versions yet)
echo -n "$NEW_SECRET" | gcloud secrets versions add mindful-money-secret --data-file=-

# 3. Redeploy Cloud Run (picks up :latest)
gcloud run deploy mindful-money \
  --region us-central1 \
  --project project-c89a7f58-b865-4112-bf8 \
  --image us-central1-docker.pkg.dev/project-c89a7f58-b865-4112-bf8/mindful-money/app:latest

# 4. Verify app is working, then disable old versions (do not destroy for 7 days)
```

### Neon database URL (neon-db-url)

**Impact:** Brief downtime during rotation.

```bash
# 1. In Neon console: reset database password
# 2. Get new connection string
# 3. Add to Secret Manager
echo -n "NEW_URL" | gcloud secrets versions add neon-db-url --data-file=-

# 4. Redeploy Cloud Run
gcloud run deploy mindful-money \
  --region us-central1 \
  --project project-c89a7f58-b865-4112-bf8 \
  --image us-central1-docker.pkg.dev/project-c89a7f58-b865-4112-bf8/mindful-money/app:latest

# 5. Run migrations to verify connectivity
# (from Cloud Shell with new URL)
```

### SimpleFin access URL

**Impact:** None (client-side only).

The SimpleFin access URL is never stored server-side. To rotate:
1. Get a new access URL from https://beta-bridge.simplefin.org/
2. Use it in the app (prompted on each connect, not stored)
3. Revoke the old URL in SimpleFin bridge settings
