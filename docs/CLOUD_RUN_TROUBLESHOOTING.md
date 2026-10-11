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
