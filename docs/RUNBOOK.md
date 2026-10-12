# Operations Runbook

**Last updated:** 2026-10-11

Quick reference for common operations.

## Deploy

Deploys happen automatically via GitHub Actions on push to `main`.
See `docs/DEPLOYMENT_WORKFLOW.md` for details.

**Manual deploy (if needed):**
```bash
# Trigger via API
python3 github-api.py call POST \
  "/repos/PaulinoTech1/Mindful-Money/actions/workflows/deploy.yml/dispatches" \
  --data '{"ref":"main"}'
```

## Rollback

```bash
# List recent revisions
gcloud run revisions list \
  --service mindful-money \
  --region us-central1 \
  --project project-c89a7f58-b865-4112-bf8

# Roll back to a previous revision
gcloud run services update-traffic mindful-money \
  --region us-central1 \
  --project project-c89a7f58-b865-4112-bf8 \
  --to-revisions <REVISION_NAME>=100
```

## Database migrations

```bash
# From Cloud Shell
export PATH="$HOME/.local/bin:$PATH"
export VAULT_DATABASE_URL=$(gcloud secrets versions access latest --secret=neon-db-url --project=project-c89a7f58-b865-4112-bf8)
cd ~/Mindful-Money/Mindful-Money

# Check current version
alembic current

# Apply pending migrations
alembic upgrade head

# Roll back one migration (dangerous - backup first)
alembic downgrade -1
```

## View logs

```bash
# Recent app logs
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=mindful-money" \
  --limit 50 --format json \
  --project=project-c89a7f58-b865-4112-bf8

# Errors only
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=mindful-money AND severity>=ERROR" \
  --limit 20 \
  --project=project-c89a7f58-b865-4112-bf8
```

## Scale

```bash
# Set min/max instances
gcloud run services update mindful-money \
  --region us-central1 \
  --project project-c89a7f58-b865-4112-bf8 \
  --min-instances 0 \
  --max-instances 10

# Current: min=0 (scale to zero), max=default (100)
# For personal use, min=0 is fine (cold starts acceptable)
```

## Secrets

See `docs/INCIDENT_RESPONSE.md` → "Secrets rotation procedures"

## Incident response

See `docs/INCIDENT_RESPONSE.md` for full runbook.

Quick triage:
1. Check Cloud Logging for errors
2. Check `/api/audit/events` for security events
3. Check Cloud Run metrics for latency/errors

## Health checks

- `GET /health` - liveness (200 if running)
- `GET /ready` - readiness (200 if DB reachable, 503 otherwise)

```bash
curl https://mindful-money-k23ukkh5cq-uc.a.run.app/health
curl https://mindful-money-k23ukkh5cq-uc.a.run.app/ready
```

## SLOs

**Availability:** 99.5% (allows ~3.6 hours downtime/month)
- Measured via Cloud Monitoring uptime check on `/health`
- Alert if down for > 10 minutes

**Latency:** p99 < 2 seconds
- Measured via Cloud Run request latency metrics
- Alert if p99 > 2s for 5 minutes

**Error rate:** < 1% of requests
- Measured via Cloud Run error rate
- Alert if > 1% for 5 minutes

These are targets, not guarantees. This is a personal project.

## Lesson: Cloud Run env vars are not Vercel env vars (2026-10-12, Boss)

**Mistake:** When setting `VAULT_BOOTSTRAP_TOKEN`, ran:

```bash
gcloud run services update mindful-money \
  --set-env-vars="<token-value-only>"
```

This failed with `Bad syntax for dict arg`.

**Root cause:** Mental model was Vercel, where you paste `KEY=value` into a
dashboard field and the platform parses it. Cloud Run's gcloud CLI expects
the full `KEY=value` pair inside the flag:

```bash
gcloud run services update mindful-money \
  --set-env-vars="VAULT_BOOTSTRAP_TOKEN=<token-value>"
```

**Rule:** With gcloud, `--set-env-vars` takes `KEY=VALUE` pairs, not bare values.
The flag name is not the variable name. This applies to `--update-env-vars`
as well. Verify with:
`gcloud run services describe mindful-money --format="value(spec.template.spec.containers[0].env)"`

## Cost caps for honeypot tarpits (2026-10-12)

The honeypot tarpits add 3-12s delays to waste attacker time. Three layers
prevent this from becoming an economic DoS vector:

### 1. Max instances (infrastructure)

The deploy workflow sets `--max-instances 3`. Cloud Run will never spin up
more than 3 instances, bounding total compute cost regardless of attack volume.

Worst case: 3 instances × 1 vCPU × 24h = ~$2/day if fully saturated.
Normal operation: 0-1 instances (scales to zero).

### 2. Per-IP rate limiting (application)

`_honeypot_rate_limited()` tracks hits per client IP in memory. More than
10 honeypot hits in 60 seconds → skip the tarpit delay, return immediately.

This means:
- Normal scanners (a few hits): get the full tarpit experience
- Flood attackers (100s of hits): get instant responses after the 10th hit

The in-memory store resets on instance restart, which is fine for abuse
mitigation. Persistent attackers get a fresh budget per instance, but the
max-instances cap bounds total cost.

### 3. Concurrency limit

`--concurrency 8` means each instance handles max 8 concurrent requests.
Combined with max-instances 3, the absolute ceiling is 24 concurrent
tarpit delays.

### Monitoring

Watch for `honeypot_rate_limited` events in logs. Frequent triggers indicate
an active flooding attempt. The webhook alert for `HONEYPOT_HIT` will also fire.

## GitHub Secrets are write-only (2026-10-12)

GitHub Actions secrets cannot be viewed after being set. The UI masks all
values permanently. If you need to recover a secret value (e.g., the
`GCP_SERVICE_ACCOUNT` email for IAM troubleshooting), don't look in GitHub.

Instead, find it on the GCP side:

```bash
# List service accounts in the project
gcloud iam service-accounts list --project=project-c89a7f58-b865-4112-bf8

# Identify which one GitHub uses: check for the Workload Identity binding
gcloud iam service-accounts get-iam-policy <candidate-email> \
  --project=project-c89a7f58-b865-4112-bf8 \
  --flatten="bindings[].members" \
  --format="table(bindings.role,bindings.members)" \
  --filter="bindings.members:github"
```

The service account with a `principalSet://.../attribute.repository/PaulinoTech1/Mindful-Money`
member is the GitHub deployer. In our case: `mindful-money-deploy@project-c89a7f58-b865-4112-bf8.iam.gserviceaccount.com`.

**Lesson:** Keep a local record of which service account maps to which secret
when you set them up. GitHub won't show you again.
