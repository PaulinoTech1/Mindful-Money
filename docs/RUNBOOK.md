# Operations Runbook

**Last updated:** 2026-10-13

Quick reference for common operations.

## Canonical hostname

`https://mindful-money-k23ukkh5cq-uc.a.run.app` is the canonical URL. It is the
only host that matches `VAULT_RP_ID` / `VAULT_ORIGIN` in
`.github/workflows/deploy.yml`, so it is the only host where passkeys work.

Cloud Run also serves the same service at
`mindful-money-31393284277.us-central1.run.app`. That host reaches the same
revision, but **it is not valid for passkeys** (WebAuthn binds to the RP ID)
and must not be used for enrollment, login, or docs. Residual risks live in
`docs/THREAT_MODEL.md`; this runbook links there rather than restating them.

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

**JS integrity note:** Rolling back to an older revision serves older JavaScript.
The CI integrity smoke test compares served JS to the manifest from the
*deployed git commit*. After a manual rollback, the served JS will NOT match
the latest commit's manifest. This is expected. To verify a rollback:
1. Identify the git commit corresponding to the revision
2. Compare served JS hashes to THAT commit's `integrity-manifest.json`
3. Do not treat a mismatch against `main` as tampering after a deliberate rollback

## Database migrations

**Rules (each one learned from an incident, see
`docs/CLOUD_RUN_TROUBLESHOOTING.md`):**

1. Run from a CURRENT checkout. The 2026-10-12 run used a stale checkout and
   stopped five revisions short without erroring.
2. Use the **UNPOOLED** Neon connection string. DDL cannot run through the
   pooler. The `neon-db-url` secret (used by Cloud Run at runtime) is the
   POOLED string, so do not export it for migrations.
3. The driver prefix must be `postgresql+psycopg://`, exactly once. The image
   ships psycopg 3 only.
4. The URL is typed with `read -s`: never in shell history, never echoed.

`migrations/env.py` refuses to run (with a message that never shows the
value) if the URL is empty, has the wrong or a doubled prefix, or points at a
`-pooler` host.

```bash
# Cloud Shell
cd ~/Mindful-Money/Mindful-Money
git pull --ff-only && git log --oneline -1   # confirm you are on current main
export PATH="$HOME/.local/bin:$PATH"
pip install --user alembic sqlalchemy "psycopg[binary]"

# Neon dashboard: Connection string with "Connection pooling" OFF
# (host has no "-pooler"). Paste at the hidden prompt.
read -rs NEON_UNPOOLED; echo
case "$NEON_UNPOOLED" in
  postgresql+psycopg://*) VAULT_DATABASE_URL="$NEON_UNPOOLED" ;;
  postgresql://*)         VAULT_DATABASE_URL="postgresql+psycopg://${NEON_UNPOOLED#postgresql://}" ;;
  postgres://*)           VAULT_DATABASE_URL="postgresql+psycopg://${NEON_UNPOOLED#postgres://}" ;;
  *)                      echo "Unrecognized scheme, aborting"; VAULT_DATABASE_URL="" ;;
esac
export VAULT_DATABASE_URL; unset NEON_UNPOOLED

alembic heads          # expected head(s) from this checkout
alembic current        # what the database is at
alembic upgrade head
alembic current        # MUST equal `alembic heads`

unset VAULT_DATABASE_URL
```

Then verify columns, not just tables (see the 2026-10-13 schema-drift entry
in `docs/CLOUD_RUN_TROUBLESHOOTING.md`), and check
`curl -s -o /dev/null -w "%{http_code}" https://mindful-money-k23ukkh5cq-uc.a.run.app/ready`.

Current state (2026-10-13): 9 revisions, head `a7b8c9d0e1f2` (applied to Neon
before merging PR #8). PR #8 deployed to Cloud Run as `dee30a5`.

```bash
# Roll back one migration (dangerous: take a Neon branch/backup first,
# see docs/BACKUP_RESTORE.md)
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
  --max-instances 3

# Current: min=0 (scale to zero), max=3. Source of truth is the
# `--max-instances 3` flag in .github/workflows/deploy.yml: every deploy
# re-applies it, so a manual change here is overwritten on the next deploy.
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
