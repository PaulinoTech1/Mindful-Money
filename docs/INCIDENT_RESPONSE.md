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
gcloud logging metrics create mm_suspicious_counter \
  --project=$PROJECT \
  --description="WebAuthn sign count regression - possible cloned authenticator" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND jsonPayload.event=\"suspicious_counter\""

# 2. Passkey auth failures (brute force indicator)
gcloud logging metrics create mm_auth_failures \
  --project=$PROJECT \
  --description="Passkey authentication failures" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND jsonPayload.event=\"passkey_auth_failure\""

# 3. Unusual activity detections
gcloud logging metrics create mm_unusual_activity \
  --project=$PROJECT \
  --description="Browser-side unusual activity detector triggered" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND jsonPayload.event=\"unusual_activity\""

# 4. Rate limiting (potential abuse)
gcloud logging metrics create mm_rate_limited \
  --project=$PROJECT \
  --description="Rate limit hits" \
  --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND jsonPayload.event=\"rate_limited\""

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
  --condition-filter="metric.type=\"logging.googleapis.com/user/mm_suspicious_counter\"" \
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
  "resource.type=cloud_run_revision AND resource.labels.service_name=\"mindful-money\" AND (jsonPayload.event=\"suspicious_counter\" OR jsonPayload.event=\"passkey_auth_failure\")" \
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
- Auth success/failure rate (from `mm_auth_failures` metric)
- Suspicious counter events (from `mm_suspicious_counter`)
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
