# Uptime Monitoring

## Free-tier Cloud Monitoring uptime check

Google Cloud Monitoring includes free uptime checks (50 checks free per
billing account). This monitors the `/health` endpoint and alerts on
consecutive failures.

### Setup via Cloud Console

1. Go to console.cloud.google.com → Monitoring → Uptime checks
2. Click "Create uptime check"
3. Configure:
   - **Title:** `mindful-money-health`
   - **Protocol:** HTTPS
   - **Hostname:** `mindful-money-k23ukkh5cq-uc.a.run.app`
   - **Path:** `/health`
   - **Port:** 443
   - **Check interval:** 5 minutes
   - **Timeout:** 10 seconds
4. Under "Alerting":
   - Create a new alert policy
   - **Condition:** Uptime check fails for 2 consecutive periods (10 minutes)
   - **Notification channel:** Email (your address)
5. Click Create

### Setup via gcloud

```bash
# Create notification channel (email)
gcloud alpha monitoring channels create \
  --display-name="mindful-money-alerts" \
  --description="Email alerts for Mindful Money downtime" \
  --type=email \
  --channel-labels=email_address=YOUR_EMAIL@example.com \
  --project=project-c89a7f58-b865-4112-bf8
# Note the channel ID from the output (e.g., projects/.../notificationChannels/123)

# Create uptime check
gcloud monitoring uptime-checks create https mindful-money-health \
  --hostname=mindful-money-k23ukkh5cq-uc.a.run.app \
  --path=/health \
  --port=443 \
  --period=300 \
  --timeout=10 \
  --project=project-c89a7f58-b865-4112-bf8

# Create alert policy (2 consecutive failures = alert)
# Note: Alert policies via gcloud require a JSON config file.
# The Console UI is simpler for one-off setup.
```

### What it monitors

- **`/health` endpoint:** Verifies the app process is running
- **Does NOT verify:** Database connectivity (use `/ready` for that),
  correct JavaScript (covered by CI smoke tests), or encryption functionality

### Alert fatigue

- 5-minute checks with 2-failure threshold = alert after 10 minutes downtime
- Cloud Run cold starts can cause single failures; the 2-consecutive
  threshold avoids false positives from cold starts

### Cost

Uptime checks: first 50 checks free per billing account per month.
This uses 1 check. **No billing impact.**

### Limitations

- Monitoring detects downtime, not compromise. A fully compromised
  origin will still return 200 on `/health`.
- For integrity monitoring (detecting JS tampering), rely on the CI
  smoke tests and periodic manual verification per `docs/JS_INTEGRITY.md`.
- Cloud Monitoring does not verify the privacy guarantees; it only
  checks availability.

## Manual status check

```bash
curl -s https://mindful-money-k23ukkh5cq-uc.a.run.app/health
# Expected: {"status": "ok"}

curl -s https://mindful-money-k23ukkh5cq-uc.a.run.app/ready
# Expected: {"status": "ready", "database": "ok"}
```
