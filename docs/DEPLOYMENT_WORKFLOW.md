# Deployment Workflow

**Last updated:** 2026-10-11
**Status:** Active

## How deploys work now

Push to `main` → GitHub Actions builds Docker image → pushes to Artifact
Registry → deploys to Cloud Run. No manual `gcloud` commands needed.

### Automatic triggers

The workflow (`.github/workflows/deploy.yml`) runs on push to `main` when
these paths change:

- `app.py`, `db.py`, `models.py`, `zkp_verifier.py`
- `static/**`
- `migrations/**`
- `requirements.txt`
- `Dockerfile`

Changes to docs, tests, or other files do not trigger a deploy.

### Manual trigger

Via GitHub UI: Actions → "Deploy to Cloud Run" → "Run workflow"

Via API:
```bash
python3 github-api.py call POST \
  "/repos/PaulinoTech1/Mindful-Money/actions/workflows/deploy.yml/dispatches" \
  --data '{"ref":"main"}'
```

### Authentication

Uses Workload Identity Federation (OIDC). No JSON keys. GitHub Actions
authenticates as the GCP Compute service account via short-lived tokens.

Required GitHub secrets:
- `GCP_WORKLOAD_IDENTITY_PROVIDER`: the WIF provider resource name
- `GCP_SERVICE_ACCOUNT`: `31393284277-compute@developer.gserviceaccount.com`

### What the workflow does

1. Checks out the repo
2. Authenticates to GCP via WIF
3. Builds Docker image, tags with commit SHA
4. Pushes to `us-central1-docker.pkg.dev/project-c89a7f58-b865-4112-bf8/mindful-money/app`
5. Deploys to Cloud Run service `mindful-money` in `us-central1`
6. Sets env vars (VAULT_ENV, VAULT_AUTH_POLICY, VAULT_RP_ID, VAULT_ORIGIN,
   VAULT_TRUST_PROXY, VAULT_CSP_MODE)
7. Attaches secrets (VAULT_SECRET_KEY, VAULT_DATABASE_URL from Secret Manager)

### Database migrations

Migrations are **not** run by the workflow. Run manually from Cloud Shell:

```bash
export PATH="$HOME/.local/bin:$PATH"
pip install alembic sqlalchemy "psycopg[binary]"
export VAULT_DATABASE_URL=$(gcloud secrets versions access latest --secret=neon-db-url)
cd ~/Mindful-Money/Mindful-Money
alembic upgrade head
```

### Why this replaced manual deploys

Previously, deploys required running `gcloud` commands in Cloud Shell:
build, push, deploy, update env vars. This was error-prone (wrong directory,
forgotten flags, IAM issues) and required context-switching between the repo
and GCP.

The GitHub Actions workflow eliminates that. Code changes go through the
normal git push flow, and deployment is automatic and auditable in the
Actions UI.

See `docs/CLOUD_RUN_TROUBLESHOOTING.md` for the full history of manual
deploy issues that motivated this change.
