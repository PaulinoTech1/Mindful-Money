# Cloud Run Deployment Troubleshooting

Issues encountered deploying Mindful Money to Google Cloud Run (2026-10-11).

## Secret Manager API not enabled

**Symptom:**
```
ERROR: (gcloud.secrets.create) Secret Manager API has not been used in project
[...] before or it is disabled.
```

**Fix:**
```bash
gcloud services enable secretmanager.googleapis.com
```
Wait 2-3 minutes for propagation before retrying.

## Cloud Build API not enabled

**Symptom:**
```
ERROR: (gcloud.run.deploy) INVALID_ARGUMENT: Invalid build request.
could not resolve source: ... does not have storage.objects.get access ...
```

**Fix:**
```bash
gcloud services enable cloudbuild.googleapis.com
```
If still failing after propagation, grant the Compute service account
explicit Storage Object Viewer:
```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

## Service account key creation blocked

**Symptom:** GCP Console shows "Service account key creation is disabled"
with `iam.disableServiceAccountKeyCreation` organization policy.

**Cause:** Google Advanced Protection mode enforces this policy.

**Workaround:** Do not use JSON keys. Options:
1. Run `gcloud` commands directly from Cloud Shell (already authenticated)
2. Use Workload Identity Federation for CI/CD (no long-lived secrets)

## Build log not found

**Symptom:**
```
(gcloud.builds.log) NOT_FOUND: Requested entity was not found.
```

**Cause:** Build ID from a previous (cleaned up) attempt, or the build
failed before logging started.

**Fix:** Rerun the deploy and use the fresh build ID from the output URL.

## VAULT_RP_ID / VAULT_ORIGIN placeholder

The initial deploy uses `placeholder` values because the Cloud Run URL
is not known until after first deploy. After getting the URL:

```bash
gcloud run deploy mindful-money \
  --region us-central1 \
  --update-env-vars "VAULT_RP_ID=actual-host.run.app,VAULT_ORIGIN=https://actual-host.run.app"
```

WebAuthn will not work until these match the real URL.

## Private service access

Deploy without `--allow-unauthenticated`, then grant invoker access:

```bash
gcloud run services add-iam-policy-binding mindful-money \
  --region us-central1 \
  --member="user:YOUR_EMAIL@gmail.com" \
  --role="roles/run.invoker"
```

## Docker build succeeds but deploy fails

**Symptom:** `gcloud builds describe` shows the `gcr.io/cloud-builders/docker`
step as SUCCESS, but overall build status is FAILURE with empty logs.

**Cause:** The failure is in the push to Artifact Registry or the Cloud Run
deployment phase, not the Docker build itself. The Dockerfile is fine.

**Diagnosis:**
```bash
# Get the latest build ID
BUILD_ID=$(gcloud builds list --region us-central1 --limit 1 --format="value(id)")

# Check step statuses
gcloud builds describe $BUILD_ID --region us-central1 --format="json(steps[].name, steps[].status)"

# Check if the service was created despite the failure
gcloud run services list --region us-central1
```

**Common causes:**
- Artifact Registry API not enabled: `gcloud services enable artifactregistry.googleapis.com`
- Insufficient permissions for the Cloud Build service account to push images
- The `--source .` upload succeeded but the image push failed silently

## Testing the build without deploying

To isolate whether the issue is the Docker build or the Cloud Run deploy:

```bash
# Build only (no deploy) - tags the image but doesn't run it
gcloud builds submit \
  --region us-central1 \
  --tag us-central1-docker.pkg.dev/PROJECT_ID/mindful-money/test:latest \
  .
```

If this succeeds, the Dockerfile is fine and the issue is in the
deploy phase (IAM, secrets, env vars). If it fails, the issue is
in the Docker build itself.

## Manual Docker build test

If Cloud Build logs are empty, test the Dockerfile locally first
(requires Docker installed):

```bash
docker build -t mindful-money-test .
```

This catches Dockerfile syntax errors, missing files, and dependency
issues before involving GCP.

## Cloud Run cannot access Secret Manager secrets

**Symptom:** Deploy fails after Docker build succeeds. The container
cannot start because it cannot read the secrets.

**Cause:** The Cloud Run runtime service account
(`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) does not have
the `secretmanager.secretAccessor` role on the secrets.

**Fix:**
```bash
PROJECT_NUMBER=$(gcloud projects describe PROJECT_ID --format="value(projectNumber)")

gcloud secrets add-iam-policy-binding mindful-money-secret \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding neon-db-url \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Artifact Registry push denied

**Symptom:** `gcloud builds submit` succeeds in building but fails pushing:
```
denied: Permission 'artifactregistry.repositories.uploadArtifacts' denied
```

**Cause:** The Artifact Registry repository does not exist, or the Cloud
Build service account lacks push permission.

**Fix:**
```bash
# Create the repository
gcloud artifacts repositories create mindful-money \
  --repository-format=docker \
  --location=us-central1

# Grant Cloud Build push access
gcloud artifacts repositories add-iam-policy-binding mindful-money \
  --location=us-central1 \
  --member="serviceAccount:PROJECT_NUMBER@cloudbuild.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"
```

## `gcloud run deploy --source` fails after Docker build succeeds

**Symptom:** Multiple `gcloud run deploy --source .` attempts fail with
"Build failed" even though `gcloud builds describe` shows the Docker step
as SUCCESS. The image never appears in Artifact Registry
(`gcloud artifacts docker images list` returns 0 items).

**What was tried:**
1. Enabled Secret Manager, Cloud Build, and Artifact Registry APIs
2. Created the Artifact Registry repository `mindful-money`
3. Granted `roles/artifactregistry.writer` to the Cloud Build service account
4. Granted `roles/storage.objectViewer` to the Compute service account
5. Granted `roles/secretmanager.secretAccessor` to the Cloud Run runtime
   service account for both secrets

**Hypothesis:** The `--source .` flow uses an internal registry path that
does not match the manually created Artifact Registry repository. The
push target is opaque and not configurable, making IAM debugging difficult.

**Next try: Separate build from deploy**

Instead of the combined `--source` flow, split into two explicit steps.
This gives full control over the image tag and registry path:

```bash
# Step 1: Build and push to our known Artifact Registry path
gcloud builds submit \
  --region us-central1 \
  --tag us-central1-docker.pkg.dev/PROJECT_ID/mindful-money/app:latest \
  .

# Step 2: Deploy from the pushed image (no build involved)
gcloud run deploy mindful-money \
  --image us-central1-docker.pkg.dev/PROJECT_ID/mindful-money/app:latest \
  --region us-central1 \
  --set-env-vars "VAULT_ENV=production,..." \
  --set-secrets "VAULT_SECRET_KEY=mindful-money-secret:latest,VAULT_DATABASE_URL=neon-db-url:latest"
```

**Justification:** If Step 1 succeeds, the Dockerfile and registry
permissions are confirmed working. If Step 2 then fails, the issue is
isolated to Cloud Run configuration (env vars, secrets, IAM), not the
build pipeline. This bisects the problem instead of debugging the
opaque combined flow.

## Cloud Build uses Compute service account, not Cloud Build SA

**Symptom:** Push to Artifact Registry fails with permission denied,
even after granting `roles/artifactregistry.writer` to
`PROJECT_NUMBER@cloudbuild.gserviceaccount.com`.

**Cause:** The build log shows:
```
The service account running this build .../serviceAccounts/PROJECT_NUMBER-compute@developer.gserviceaccount.com
```
Cloud Build is using the Compute Engine default service account, not
the Cloud Build service account. The IAM grant went to the wrong identity.

**Fix:** Grant the role to the Compute service account instead:
```bash
gcloud artifacts repositories add-iam-policy-binding mindful-money \
  --location=us-central1 \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"
```

## Alembic not found after pip install in Cloud Shell

**Symptom:** `pip install alembic` succeeds but `alembic: command not found`.

**Cause:** Cloud Shell installs user packages to `~/.local/lib/python3.12/site-packages`
with binaries in `~/.local/bin`, which is not in the default PATH.

**Fix:**
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Or use the module directly:
```bash
python3 -m alembic upgrade head
```

## Running migrations from Cloud Shell

```bash
export PATH="$HOME/.local/bin:$PATH"
pip install alembic sqlalchemy "psycopg[binary]"
export VAULT_DATABASE_URL=$(gcloud secrets versions access latest --secret=neon-db-url)
cd ~/Mindful-Money/Mindful-Money
alembic upgrade head
```

The secret value stays in the shell environment and is never printed
or pasted into chat.

## App returns 500: Could not parse SQLAlchemy URL

**Symptom:** Cloud Run logs show:
```
sqlalchemy.exc.ArgumentError: Could not parse SQLAlchemy URL from given URL string
```
at `db.py` line 30 in `_ensure_bound()` when calling `create_engine()`.

**Cause:** The `VAULT_DATABASE_URL` secret contains an invalid value.
Common cases:
- Still has the placeholder text from initial setup
- Missing the `postgresql://` scheme prefix
- Truncated or has a trailing newline issue
- Special characters in the password not URL-encoded

**Diagnosis:** Check the secret length without printing it:
```bash
gcloud secrets versions access latest --secret=neon-db-url | wc -c
```
A valid Neon URL is 80+ characters. If it's under 50, it's the placeholder.

**Fix:** Add a new version with the real URL using `read -s` to avoid
shell history:
```bash
read -s NEON_URL
# Paste the URL when prompted (hidden input), press Enter
echo -n "$NEON_URL" | gcloud secrets versions add neon-db-url --data-file=-
unset NEON_URL
```

The Cloud Run revision uses `neon-db-url:latest`, so it picks up the new
version on the next container startup. If the app is already running,
trigger a new revision:
```bash
gcloud run deploy mindful-money \
  --image us-central1-docker.pkg.dev/PROJECT_ID/mindful-money/app:latest \
  --region us-central1
```

**Valid format:**
```
postgresql://user:password@ep-xxx-xxx.us-east-2.aws.neon.tech/dbname?sslmode=require
```
Use the pooled connection string from the Neon dashboard (contains `-pooler`
in the hostname).

## Decision: Secrets via Secret Manager, never shell history

**Context:** The Neon database URL and Flask secret key are sensitive
credentials. They needed to get into GCP Secret Manager securely.

**Options considered:**

1. **Direct `echo` in shell** (rejected)
   ```bash
   echo -n "postgresql://..." | gcloud secrets create neon-db-url --data-file=-
   ```
   The URL appears in shell history (`~/.bash_history`). Anyone with
   access to the Cloud Shell VM or its disk image could recover it.
   Rejected.

2. **`read -s` with hidden input** (acceptable fallback)
   ```bash
   read -s NEON_URL
   echo -n "$NEON_URL" | gcloud secrets versions add neon-db-url --data-file=-
   unset NEON_URL
   ```
   Input is hidden, doesn't appear in history. The variable is cleared
   after use. Acceptable but requires careful execution.

3. **GCP Console web UI** (chosen)
   Navigate to Secret Manager in the browser, click the secret,
   "New Version", paste the value. No shell involved at all.

**Decision:** Use the GCP Console web UI for initial secret creation.
The browser session is already authenticated with Advanced Protection
+ YubiKey. No credential touches the shell, its history, or any log.

**Rationale:** For a finance app, the database credential is the highest-
value secret. The extra clicks in the web UI are worth eliminating
the shell history risk entirely. The `read -s` method is documented
as a fallback for automation, but manual web UI entry is preferred
for one-time setup.

## Frontend calls removed API endpoint (ZK refactor leftover)

**Symptom:** Browser console shows:
```
/api/relay/sources:1 Failed to load resource: 404
app.js:28 Uncaught (in promise) Error: Request failed.
    at apiFetch (app.js:28:19)
    at async app.js:1488:19
```
The app stuck on "Loading cryptography..." and never proceeds.

**Cause:** The zero-knowledge refactor removed the server-side SimpleFin
relay (`/api/relay` and `/api/relay/sources`), but `static/app.js` still
called `/api/relay/sources` during boot to check if SimpleFin was available.
The 404 threw an uncaught promise rejection that halted initialization
before libsodium could finish loading.

**Fix:** Remove the call. SimpleFin is now always available client-side
(it's just JavaScript in `simplefin-client.js`). In `static/app.js`:
```javascript
// Before:
const sources = await api('/api/relay/sources'); SIMPLEFIN_AVAILABLE = sources.simplefin_available;
// After:
SIMPLEFIN_AVAILABLE = true;
```

**Lesson:** When removing server endpoints, grep the frontend for all
references. The refactor removed the Flask routes but missed the JS
caller. A pre-deploy checklist should include: "search frontend for
removed endpoint paths."

## Current deployment status (2026-10-11)

**Working:**
- Cloud Run service deployed and running
- Database migrations completed (3 migrations applied)
- Secrets in Secret Manager (Flask key, Neon URL)
- WebAuthn RP_ID/ORIGIN configured for the Cloud Run URL
- Docker build pipeline functional

**Not working:**
- Frontend boot blocked by the `/api/relay/sources` 404 (fix pushed,
  awaiting redeploy)
- Browser IAM access: Cloud Run IAM incompatible with browser navigation,
  removed in favor of app-level WebAuthn

**Honest assessment:** The infrastructure is solid. The app deploys,
connects to the database, and serves pages. The remaining issue is a
frontend bug from an incomplete refactor, not an infrastructure problem.
Once the fixed `app.js` is deployed, the app should be fully functional.

## GitHub Actions WIF: service account impersonation denied

**Symptom:** GitHub Actions workflow authenticates via Workload Identity
Federation successfully, but the Docker push fails with:
```
ERROR: (gcloud.auth.docker-helper) There was a problem refreshing your
current auth tokens: ('Unable to acquire impersonated credentials',
'Permission iam.serviceAccounts.getAccessToken denied on resource
(or it may not exist).')
```

**Cause:** The Workload Identity Pool was granted `roles/run.admin`,
`roles/artifactregistry.writer`, and `roles/iam.serviceAccountUser` at
the project level. But `serviceAccountUser` is not sufficient for
Workload Identity Federation impersonation. The pool needs the
`roles/iam.workloadIdentityUser` role **on the specific service account**
being impersonated.

**Fix:**
```bash
gcloud iam service-accounts add-iam-policy-binding SERVICE_ACCOUNT_EMAIL \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.repository/ORG/REPO" \
  --role="roles/iam.workloadIdentityUser"
```

**Why this is easy to miss:** The GCP docs for Workload Identity
Federation emphasize the pool-level IAM grants (run.admin, etc.), but
the service-account-level `workloadIdentityUser` binding is documented
separately under "impersonation." The error message
(`getAccessToken denied`) does not name the missing role directly.

**Complete WIF setup checklist for Cloud Run deploys:**
1. Create workload identity pool
2. Create OIDC provider for `https://token.actions.githubusercontent.com`
   with attribute condition on the repo
3. Grant pool `roles/run.admin` on the project
4. Grant pool `roles/artifactregistry.writer` on the Artifact Registry repo
5. Grant pool `roles/iam.workloadIdentityUser` **on the service account**
   (this is the step most often missed)
6. Add `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_SERVICE_ACCOUNT` as
   GitHub Actions secrets

## GitHub Actions: gcloud uses wrong project

**Symptom:** Workflow fails at "Deploy to Cloud Run" with:
```
ERROR: (gcloud.run.deploy) PERMISSION_DENIED: Cloud Run Admin API has not
been used in project developer before or it is disabled.
```

**Cause:** The `gcloud` CLI in the GitHub Actions runner defaults to a
project named `developer` (derived from the service account credentials)
instead of the actual GCP project. The `--project` flag was missing from
the deploy command.

**Fix:** Add `--project ${{ env.PROJECT_ID }}` explicitly to all `gcloud`
commands in the workflow:
```yaml
gcloud run deploy ${{ env.SERVICE_NAME }} \
  --image "${{ env.IMAGE }}" \
  --region ${{ env.REGION }} \
  --project ${{ env.PROJECT_ID }} \
  ...
```

**Lesson:** Never rely on gcloud's default project in CI. The credential
file override (`gha-creds-*.json`) sets an unexpected default. Always
pass `--project` explicitly in automation.

## Service account cannot act as itself (iam.serviceAccounts.actAs)

**Symptom:**
```
ERROR: (gcloud.run.deploy) PERMISSION_DENIED: The service account
31393284277-compute@developer.gserviceaccount.com does not have
iam.serviceAccounts.actAs permission on itself.
```

**Root cause:** Cloud Run deploy needs the deploying service account to
impersonate the runtime service account (which is itself in this case).

**Fix:** (run from Cloud Shell)
```bash
gcloud iam service-accounts add-iam-policy-binding \
  31393284277-compute@developer.gserviceaccount.com \
  --member="serviceAccount:31393284277-compute@developer.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser" \
  --project=project-c89a7f58-b865-4112-bf8
```

Wait 2-3 minutes for IAM propagation, then re-run the workflow.

## _seed_identity NotNullViolation on passkey_required (2026-10-12)

**Symptom:** Every `/api/*` request returns 503 with
`{"error":"The request could not be completed"}`. `/health` returns 200.
Smoke tests fail on `/api/version` and `/api/passkeys/status`. No error
appears in Cloud Run logs because the `SQLAlchemyError` handler does not
log the exception.

**Root cause:** `_seed_identity()` in `db.py` inserts the bootstrap
identity row with only `id` and `user_handle`, relying on the Python-side
`default=False` for the `passkey_required` column. That default does not
fire on a Core `pg_insert` (it is an ORM-flush behavior), so PostgreSQL
receives NULL for a NOT NULL column with no server default:

```
psycopg.errors.NotNullViolation: null value in column "passkey_required"
of relation "vault_identity" violates not-null constraint
```

The rate limiter's `before_request` handler calls `db()` on every
`/api/*` request, which calls `_seed_identity()`, so a single missing
default takes down the entire API surface while `/health` (no DB touch)
stays green.

**Fix:** Set the value explicitly instead of relying on the default
(`db.py`):

```python
.values(id=1, user_handle=secrets.token_bytes(32), passkey_required=False)
```

**Lesson:** Python-side column `default=` is not a substitute for a
database `server_default` when using Core inserts (`pg_insert`,
`insert()`). Either set values explicitly on Core inserts or add a
`server_default` to the model. Silent error handlers
(`@app.errorhandler(SQLAlchemyError)` returning 503 without logging)
make this class of bug invisible in Cloud Logging; consider logging the
exception before returning the generic error.

**Diagnosis pattern:** reproduce the app's exact DB code path from Cloud
Shell using the Secret Manager value directly (no paste):

```bash
export VAULT_DATABASE_URL=$(gcloud secrets versions access latest --secret=neon-db-url)
python3 -c 'import os; from sqlalchemy import create_engine, inspect; e = create_engine(os.environ["VAULT_DATABASE_URL"]); print(sorted(inspect(e).get_table_names()))'
```

## /api/* 503 from schema drift; kdf_version hypothesis tested and rejected (2026-10-13)

**Symptom:** After the `_seed_identity` fix (previous entry) and a
credential rotation, `/health` returns 200 but every `/api/*` request
still returns the handled 503.

**Context (same window, separately confirmed faults):**

1. The `neon-db-url` secret held a `postgresql://` URL while the image
   ships only psycopg3, so SQLAlchemy's default psycopg2 dialect failed
   to load. Cloud Shell masked this: it has psycopg2 installed, so
   direct tests against the same secret value passed there.
2. The first rotated secret version (v4) was built with the
   `postgresql+psycopg://` prefix applied twice. SQLAlchemy parses
   `postgresql+psycopg://postgresql+psycopg://user@host/db` with
   username `postgresql+psycopg`, so Postgres rejected authentication
   and every route returned 500 (the custom session interface writes
   to the DB on the response path, `app.py` `save_session`). Diagnosed
   from the Cloud Logging traceback plus a local `make_url` parse
   check. A start-of-string prefix check did not catch the doubling;
   count occurrences instead. v5 (single prefix) fixed authentication.

**Root cause (confirmed):** schema drift. The production
`vault_identity` table has 5 columns (`id`, `user_handle`,
`passkey_required`, `created_at`, `updated_at`); `models.py` maps 10.
The migrations that add the other five were never applied to the
production database: `c4d9e3f2a1b6_add_kdf_salts` (`kdf_salt_enc`,
`kdf_salt_idx`, `kdf_version`) and `f1a2b3c4d5e6_add_recovery_blob`
(`recovery_blob`, `recovery_created_at`). Inserts name their columns
explicitly, so the seed and health paths pass. Selects built from the
model's `Table` object name every mapped column, so identity-touching
`/api/*` calls fail on the missing columns (a `SQLAlchemyError`) and
the handler returns 503.

**Hypothesis tested and rejected:** that `kdf_version` was a second
`_seed_identity` landmine of the same class as `passkey_required`
(NOT NULL, Python-only `default=1`, omitted from the Core insert).
Tested from Cloud Shell against the production database: an
`information_schema` probe of `vault_identity`, plus the app's exact
insert run as-is and with `kdf_version=1` added. Result: the column
does not exist in the production table at all; the as-is insert
succeeds, and the with-`kdf_version` variant errors with "Unconsumed
column names: kdf_version". The theory was wrong. The probe is what
killed it, and the same probe is what exposed the drift.

**Fix:** apply the outstanding migrations from a current checkout
with the unpooled connection string (DDL cannot run through the
pooler):

```bash
alembic upgrade head
```

No redeploy is required: the running code already expects the full
schema and generates SQL per request.

**Lesson:** after any migration run, verify the applied state against
the models (`alembic current` versus `alembic heads`, plus a column
probe), not just the table list. A table existing is not evidence that
its columns match the models. Drift of this kind breaks selects while
inserts keep passing, which makes the failure look like an application
bug instead of a deployment gap.
