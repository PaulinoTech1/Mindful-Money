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
